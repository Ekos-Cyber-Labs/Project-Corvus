"""Wazuh-side parity bundle, offline (nothing executed against a server).

:func:`build_bundle` assembles the four bundle files for one stored
rule entirely in memory (a refusal writes nothing anywhere):

- ``wazuh_rule.xml`` — the ``<group>`` block to append to the
  manager's ``local_rules.xml`` (shadow first);
- ``logtest_input.jsonl`` — one JSON object per line with the RAW
  ``full_log`` plus the ``location`` and ``agent`` fields, the log
  format ``wazuh-logtest`` expects;
- ``expected.json`` — per line whether the rule must fire, taken
  from the Sigma engine's own matches (fresh evaluation of the
  stored text over both stores);
- ``deploy_plan.txt`` — file to edit, configuration test
  (``wazuh-analysisd -t``), restart, rollback (remove the group,
  test, restart) and the archives-but-not-alerts check. The command
  to reach the manager is NOT in the bundle: the runner reads it
  from :envvar:`CORVUS_WAZUH_LOGTEST_CMD`.

Line selection (documented, deterministic): every bundled line
resolves through the replay provenance ``(file, line)`` numbers.
Targets are the rule's backtest target events (chain store). The
baseline sample holds every mapped baseline line from the
process-execution decoders (``sudo``, ``auditd``) holding a rule
literal in plain or hex form (the plausible-match set, uncapped so
nothing plausible is silently dropped), plus the first
``BASELINE_CONTEXT_CAP`` other mapped lines of those decoders in
``(file, line)`` order as must-not-fire context. Unmapped raw lines
carry no Sigma verdict and are excluded on purpose. Counts land in
``expected.json`` so a blown-up plausible set is visible.
"""

from __future__ import annotations

import gzip
import json
import tempfile
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from corvus.learning.wazuh_xml import TranslationReport, translate

__all__ = [
    "BASELINE_CONTEXT_CAP",
    "BUNDLE_FILES",
    "DEPLOY_PLAN_NAME",
    "EXPECTED_NAME",
    "INPUTS_NAME",
    "TARGET_DECODERS",
    "XML_NAME",
    "BundleLine",
    "ExportError",
    "build_bundle",
    "read_raw_doc",
    "sigma_matches",
    "write_bundle",
]

#: Bundle file names.
XML_NAME = "wazuh_rule.xml"
INPUTS_NAME = "logtest_input.jsonl"
EXPECTED_NAME = "expected.json"
DEPLOY_PLAN_NAME = "deploy_plan.txt"
BUNDLE_FILES = (XML_NAME, INPUTS_NAME, EXPECTED_NAME, DEPLOY_PLAN_NAME)

#: Decoders carrying a process execution (the rule's match surfaces).
TARGET_DECODERS = frozenset({"sudo", "auditd"})

#: Deterministic context sample of non-plausible same-decoder lines.
BASELINE_CONTEXT_CAP = 200

#: Manager-side path edited on deploy (documented in the plan).
MANAGER_RULES_PATH = "/var/ossec/etc/rules/local_rules.xml"


class ExportError(RuntimeError):
    """The bundle cannot be built (nothing is written)."""


@dataclass(frozen=True)
class BundleLine:
    """One bundled raw line with its Sigma verdict."""

    key: int
    event_uid: str
    decoder: str
    location: str
    agent: Mapping[str, Any]
    log: str
    source_file: str
    source_line: int
    must_fire: bool


def _open_text(path: Path):
    """Open a plain or gzipped archive file for reading."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def read_raw_doc(data_dir: str | Path, file: str, line: int) -> dict[str, Any]:
    """Return one raw archive document by provenance ``(file, line)``.

    Raises :class:`ExportError` for out-of-root files, missing
    files, bad line numbers and malformed JSON: callers fail closed.
    """
    base = Path(data_dir).resolve()
    candidate = (base / file).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ExportError(f"provenance file escapes the data root: {file!r}") from None
    if line < 1:
        raise ExportError(f"provenance line out of range: {line}")
    try:
        handle = _open_text(candidate)
    except OSError as exc:
        raise ExportError(f"cannot read archive file {file!r}: {exc}") from None
    with handle:
        for _ in range(line - 1):
            if not handle.readline():
                raise ExportError(f"line {line} past end of {file!r}")
        text = handle.readline()
    if not text.strip():
        raise ExportError(f"line {line} of {file!r} is empty")
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ExportError(f"line {line} of {file!r} is not JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise ExportError(f"line {line} of {file!r} is not an object")
    return doc


def load_provenance(replay_dir: str | Path) -> dict[str, tuple[str, int]]:
    """Map every event uid in a replay store to ``(file, line)``."""
    import pyarrow.parquet as pq

    index: dict[str, tuple[str, int]] = {}
    for path in sorted(Path(replay_dir, "provenance").glob("*.parquet")):
        for row in pq.read_table(path).to_pylist():
            uid = row.get("uid")
            if isinstance(uid, str) and uid:
                index[uid] = (str(row.get("file")), int(row.get("line")))
    return index


def sigma_matches(
    sigma_text: str, chain_dir: str | Path, baseline_dir: str | Path
) -> set[str]:
    """Evaluate the stored Sigma text; return the matched event uids.

    Same loader, engine and mapping as the shipped rules (one
    temporary rule file, all statuses). Raises :class:`ExportError`
    when the text no longer compiles — e.g. edited in the database
    to something unsupported.
    """
    from corvus.detect.engine import evaluate
    from corvus.detect.rules import ALL_STATUSES, load_rules

    with tempfile.TemporaryDirectory(prefix="export-wazuh") as tmp:
        candidate = Path(tmp) / "candidate.yml"
        candidate.write_text(sigma_text, encoding="utf-8")
        try:
            compiled, _stats = load_rules(candidate.parent, statuses=ALL_STATUSES)
        except Exception as exc:
            raise ExportError(f"stored Sigma does not load: {exc}") from None
    if len(compiled) != 1:
        raise ExportError("stored Sigma does not compile to one rule")
    item = compiled[0]
    try:
        chain_matches, _, _ = evaluate(str(chain_dir), [item])
        base_matches, _, _ = evaluate(str(baseline_dir), [item])
    except Exception as exc:
        raise ExportError(f"Sigma evaluation failed: {exc}") from None
    return set(chain_matches.get(item.rule_id, set())) | set(
        base_matches.get(item.rule_id, set())
    )


def _screening_terms(report: TranslationReport) -> list[str]:
    """Lower-cased plain and hex screening terms for the baseline."""
    terms = [term.lower() for term in report.detail.get("literals", ())]
    terms.extend(term.lower() for term in report.detail.get("literal_hex", ()))
    return sorted({term for term in terms if term})


def _target_uids(row: Mapping[str, Any]) -> list[str]:
    """Return the rule's backtest target event uids from lineage."""
    lineage = row.get("lineage") or {}
    backtest = lineage.get("backtest") or {}
    matched = backtest.get("target_matched") or []
    cited = lineage.get("cited_uids") or []
    ordered = [str(uid) for uid in matched if isinstance(uid, str) and uid]
    for uid in cited:
        if isinstance(uid, str) and uid and uid not in ordered:
            ordered.append(uid)
    if not ordered:
        raise ExportError("the stored rule names no target events")
    return ordered


def _bundle_line(
    key: int,
    uid: str,
    doc: Mapping[str, Any],
    source_file: str,
    source_line: int,
    matched: set[str],
) -> BundleLine:
    """Build one bundle line; raise :class:`ExportError` when rawless."""
    decoder = doc.get("decoder")
    name = decoder.get("name") if isinstance(decoder, dict) else None
    if not isinstance(name, str) or not name:
        raise ExportError(f"target {uid} has no decoder name")
    log = doc.get("full_log")
    if not isinstance(log, str) or not log:
        raise ExportError(f"target {uid} has no full_log")
    location = doc.get("location")
    if not isinstance(location, str) or not location:
        raise ExportError(f"target {uid} has no location")
    agent = doc.get("agent")
    if not isinstance(agent, dict):
        raise ExportError(f"target {uid} has no agent block")
    return BundleLine(
        key=key,
        event_uid=uid,
        decoder=name,
        location=location,
        agent=dict(agent),
        log=log,
        source_file=source_file,
        source_line=source_line,
        must_fire=uid in matched,
    )


def _iter_baseline_docs(baseline_dir: str | Path, data_dir: str | Path) -> Any:
    """Yield ``(file, line, doc)`` over baseline source files, once each."""
    seen: set[str] = set()
    for path in sorted(Path(baseline_dir, "provenance").glob("*.parquet")):
        import pyarrow.parquet as pq

        for row in pq.read_table(path, columns=["file"]).to_pylist():
            file = str(row.get("file"))
            if file not in seen:
                seen.add(file)
    for file in sorted(seen):
        base = Path(data_dir).resolve()
        candidate = (base / file).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            raise ExportError(
                f"provenance file escapes the data root: {file!r}"
            ) from None
        try:
            handle = _open_text(candidate)
        except OSError as exc:
            raise ExportError(f"cannot read archive file {file!r}: {exc}") from None
        with handle:
            for lineno, text in enumerate(handle, start=1):
                if not text.strip():
                    continue
                try:
                    doc = json.loads(text)
                except ValueError:
                    continue
                if isinstance(doc, dict):
                    yield file, lineno, doc


def render_deploy_plan(
    *,
    title: str,
    rule_db_id: int,
    sigma_rule_id: str,
    native_ids: tuple[int, int],
    mode: str,
    levels: Mapping[str, int],
    parents: Mapping[str, Sequence[int]],
    group: str,
    target_n: int,
    baseline_n: int,
    plausible_n: int,
) -> str:
    """Render the plain-text shadow deploy plan (no manager address)."""
    from corvus.learning.logtest import BRIDGE_CONTRACT

    sudo_chain = ", ".join(str(pid) for pid in parents.get("sudo", ()))
    audit_chain = ", ".join(str(pid) for pid in parents.get("auditd", ()))
    return f"""Corvus Wazuh deploy plan (offline bundle -- nothing was executed)

Rule: {title}
  stored rule id: {rule_db_id}   sigma: {sigma_rule_id}
  native rule ids: {native_ids[0]} (sudo, level {levels["sudo"]})
  + {native_ids[1]} (auditd, level {levels["auditd"]})
  mode: {mode}   group: {group}
  bundle: {target_n} target lines, {baseline_n} baseline lines
  ({plausible_n} plausible-match, rest context sample)

Parent chains (first matching sibling wins, so each rule hangs
under the decoder group root and every stock sibling that could
match one of its records first):
  sudo if_sid: {sudo_chain}
  auditd if_sid: {audit_chain}

1. Append {XML_NAME} to {MANAGER_RULES_PATH} on the manager
   (the file holds one <group name="{group},"> block; paste it after
   the existing groups, keeping the XML well-formed).
2. Test the configuration on the manager:  wazuh-analysisd -t
   (must print no error; fix the XML, never skip this step).
3. Restart the manager:  systemctl restart wazuh-manager
4. Feed the bundle lines through wazuh-logtest from a host that can
   reach the manager. {BRIDGE_CONTRACT["in"]} {BRIDGE_CONTRACT["out"]}
   {BRIDGE_CONTRACT["command"]}

   Run:  corvus rules logtest {rule_db_id} --bundle <DIR> --out parity.json
5. Shadow check: alerts for these events are unchanged in count and
   level, now carrying the corvus_shadow group. A matching child
   replaces its parent's alert, so each shadow rule sits at the
   highest level among the parents it replaces (sudo
   level {levels["sudo"]}, auditd level {levels["auditd"]}):
   no existing alert is hidden or downgraded. Query the archives and
   the alerts for rule ids {native_ids[0]}/{native_ids[1]} and
   compare against the pre-deploy baseline.
   Active note: promotion raises both rules to level 7. An active
   rule at a higher level replaces the parent's alert with its own
   (same event, new level, corvus_active group).

Rollback (instant silence):
  remove the <group name="{group},"> block from {MANAGER_RULES_PATH},
  run wazuh-analysisd -t, restart the manager.
"""


def build_bundle(
    *,
    row: Mapping[str, Any],
    mode: str = "shadow",
    chain_dir: str | Path = "data/replay-linux-chain1",
    baseline_dir: str | Path = "data/replay-linux-baseline",
    data_dir: str | Path = "data",
    ruleset_dir: str | Path = "data/wazuh-ruleset",
    store_ids: Collection[int] = (),
    attack: Any | None = None,
) -> dict[str, str]:
    """Build the four bundle files in memory; raise :class:`ExportError`.

    ``row`` is the stored rule mapping (``get_rule`` shape).
    ``store_ids`` holds every native id already stored (plus the
    local ruleset ids, read here). Parent chains are computed from
    the shipped ruleset files (everything in ``ruleset_dir`` except
    ``local_rules.xml``). Nothing is written: callers pass the
    result to :func:`write_bundle`.
    """
    from corvus.learning.wazuh_xml import local_rules_ids, shipped_ruleset_paths

    try:
        ruleset_ids = local_rules_ids(Path(ruleset_dir) / "local_rules.xml")
    except (OSError, ValueError) as exc:
        raise ExportError(f"cannot read ruleset ids: {exc}") from None
    try:
        shipped_paths = shipped_ruleset_paths(ruleset_dir)
    except (OSError, ValueError) as exc:
        raise ExportError(f"cannot read shipped ruleset: {exc}") from None
    native = row.get("native_rule_id")
    if isinstance(native, bool) or not isinstance(native, int):
        raise ExportError("the stored rule has no native rule id")
    # The row's own native id anchors the pair (it is not deployed
    # yet); everything else taken stays excluded.
    excludes = (set(ruleset_ids) | set(store_ids)) - {native}
    report = translate(
        str(row.get("sigma_text") or ""),
        native,
        mode,
        ruleset_paths=shipped_paths,
        exclude_ids=excludes,
        attack=attack,
    )
    if not report.ok or report.xml is None:
        raise ExportError(f"{report.code}: {report.reason}")
    assert report.native_rule_ids is not None
    matched = sigma_matches(str(row.get("sigma_text") or ""), chain_dir, baseline_dir)
    chain_prov = load_provenance(chain_dir)
    lines: list[BundleLine] = []
    key = 0
    for uid in _target_uids(row):
        if uid not in chain_prov:
            raise ExportError(f"target event {uid} is not in the chain store")
        source_file, source_line = chain_prov[uid]
        doc = read_raw_doc(data_dir, source_file, source_line)
        lines.append(_bundle_line(key, uid, doc, source_file, source_line, matched))
        key += 1
    # Every other chain event the Sigma engine matches is a
    # must-fire line too, even when the proposal did not cite it.
    for uid in sorted(set(matched) & set(chain_prov) - {e.event_uid for e in lines}):
        source_file, source_line = chain_prov[uid]
        doc = read_raw_doc(data_dir, source_file, source_line)
        lines.append(_bundle_line(key, uid, doc, source_file, source_line, matched))
        key += 1
    baseline_prov = load_provenance(baseline_dir)
    by_location = {(f, n): uid for uid, (f, n) in baseline_prov.items()}
    terms = _screening_terms(report)
    plausible: list[BundleLine] = []
    context: list[BundleLine] = []
    malformed = 0
    for file, lineno, doc in _iter_baseline_docs(baseline_dir, data_dir):
        decoder = doc.get("decoder")
        name = decoder.get("name") if isinstance(decoder, dict) else None
        if name not in TARGET_DECODERS:
            continue
        baseline_uid = by_location.get((file, lineno))
        if baseline_uid is None:
            continue  # unmapped lines carry no Sigma verdict
        blob = doc.get("full_log")
        lowered = blob.lower() if isinstance(blob, str) else ""
        try:
            entry = _bundle_line(
                key + len(plausible) + len(context),
                baseline_uid,
                doc,
                file,
                lineno,
                matched,
            )
        except ExportError:
            malformed += 1
            continue
        if baseline_uid in matched or any(term in lowered for term in terms):
            # A Sigma hit is plausible by construction, even past
            # the literal screen.
            plausible.append(entry)
        elif len(context) < BASELINE_CONTEXT_CAP:
            context.append(entry)
    renumbered: list[BundleLine] = []
    for index, entry in enumerate([*lines, *plausible, *context]):
        renumbered.append(
            BundleLine(
                key=index,
                event_uid=entry.event_uid,
                decoder=entry.decoder,
                location=entry.location,
                agent=entry.agent,
                log=entry.log,
                source_file=entry.source_file,
                source_line=entry.source_line,
                must_fire=entry.must_fire,
            )
        )
    target_n = len(lines)
    inputs = (
        "\n".join(
            json.dumps(
                {
                    "key": entry.key,
                    "location": entry.location,
                    "agent": dict(entry.agent),
                    "log": entry.log,
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            for entry in renumbered
        )
        + "\n"
    )
    levels = {str(k): int(v) for k, v in report.detail.get("levels", {}).items()}
    parents = {
        str(k): [int(pid) for pid in v]
        for k, v in report.detail.get("parents", {}).items()
    }
    expected = {
        "rule_db_id": int(row.get("id") or 0),
        "sigma_rule_id": report.sigma_rule_id,
        "native_rule_ids": list(report.native_rule_ids),
        "mode": mode,
        "group": report.group,
        "level": report.level,
        "levels": levels,
        "parents": parents,
        "mitre_ids": list(report.mitre_ids),
        "counts": {
            "inputs": len(renumbered),
            "target": target_n,
            "baseline": len(renumbered) - target_n,
            "plausible": len(plausible),
            "context": len(context),
            "malformed_skipped": malformed,
            "must_fire": sum(1 for entry in renumbered if entry.must_fire),
        },
        "lines": [
            {
                "key": entry.key,
                "event_uid": entry.event_uid,
                "decoder": entry.decoder,
                "must_fire": entry.must_fire,
                "source": {"file": entry.source_file, "line": entry.source_line},
            }
            for entry in renumbered
        ],
    }
    plan = render_deploy_plan(
        title=str(row.get("title") or ""),
        rule_db_id=int(row.get("id") or 0),
        sigma_rule_id=str(report.sigma_rule_id or ""),
        native_ids=report.native_rule_ids,
        mode=mode,
        levels={k: int(v) for k, v in report.detail.get("levels", {}).items()},
        parents={
            k: [int(pid) for pid in v]
            for k, v in report.detail.get("parents", {}).items()
        },
        group=str(report.group or ""),
        target_n=target_n,
        baseline_n=len(renumbered) - target_n,
        plausible_n=len(plausible),
    )
    return {
        XML_NAME: report.xml,
        INPUTS_NAME: inputs,
        EXPECTED_NAME: json.dumps(expected, indent=2, sort_keys=True) + "\n",
        DEPLOY_PLAN_NAME: plan,
    }


def write_bundle(bundle: Mapping[str, str], out_dir: str | Path) -> Path:
    """Write a built bundle atomically; raise :class:`ExportError`.

    Refuses a non-empty existing directory (never overwrites, never
    leaves a partial bundle): files land in a temporary sibling and
    the directory is moved into place.
    """
    import shutil
    import tempfile as tempfile_module

    missing = [name for name in BUNDLE_FILES if name not in bundle]
    if missing:
        raise ExportError(f"bundle lacks files: {missing}")
    out = Path(out_dir)
    if out.exists():
        if not out.is_dir():
            raise ExportError(f"output exists and is not a directory: {out}")
        if any(out.iterdir()):
            raise ExportError(f"output directory is not empty: {out}")
    else:
        parent = out.parent if str(out.parent) else Path(".")
        parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile_module.mkdtemp(prefix="corvus-bundle-", dir=str(out.parent)))
    try:
        for name in BUNDLE_FILES:
            (tmp / name).write_text(bundle[name], encoding="utf-8")
        if out.exists():
            for name in BUNDLE_FILES:
                shutil.move(str(tmp / name), str(out / name))
            tmp.rmdir()
        else:
            shutil.move(str(tmp), str(out))
    except ExportError:
        raise
    except Exception as exc:
        raise ExportError(f"cannot write bundle: {exc}") from None
    finally:
        if tmp.exists() and any(tmp.iterdir()):
            shutil.rmtree(tmp, ignore_errors=True)
    return out
