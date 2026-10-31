"""Deterministic backtest for proposed Sigma rules (Linux, no model calls).

:func:`backtest` takes the Sigma YAML text of one candidate rule and a
target — either a set of event uids (``{"event_uids": [...]}``) or a
host plus time window
(``{"host": ..., "start": ..., "end": ...}`` with ISO-8601 instants or
epoch milliseconds) — and returns a structured result. It never
raises on bad input: every failure is a stable rejection code.

The candidate compiles and evaluates through the same engine and
mapping as the shipped rules (one temporary rule file through
:func:`corvus.detect.rules.load_rules` and
:func:`corvus.detect.engine.evaluate`), never a second copy of the
logic. Baseline matches are uids only (count, per host, up to 10
sample uids), never raw events.

Deterministic acceptance, each reason a stable code:

- ``accepted`` — the only code on success;
- ``bad_input`` — the YAML text or the target is not the documented shape;
- ``too_large`` — the YAML exceeds ``MAX_RULE_BYTES``;
- ``yaml_bomb`` — the alias/anchor screen tripped (entity-expansion suspect);
- ``too_deep`` — the indentation screen tripped (nesting suspect);
- ``timeout`` — parsing or evaluation exceeded its wall-clock budget;
- ``parse_error`` — pySigma rejected the YAML (message verbatim, capped);
- ``rule_count`` — the YAML holds zero or more than one rule;
- ``unroutable`` — the logsource has no OCSF slice (auditd-service and
  syslog/sshd/cron shapes stay out of scope);
- ``unmapped_field`` — the rule needs a field with no slot (never
  evaluated against null);
- ``unsupported_construct`` — conversion failed (legacy conditions,
  rejected regex, correlation rules);
- ``exclusion`` — more than ``MAX_EXCLUSIONS`` negations: an exclusion
  can hide an attacker, so only one narrow carve-out is tolerated;
- ``over_broad_literal`` — a ``contains``/``startswith``/``endswith``
  (or wildcard) literal shorter than ``MIN_LITERAL_LEN`` characters;
- ``leading_wildcard_regex`` — a ``|re`` pattern anchored nowhere;
- ``dangerous_regex`` — a ``|re`` pattern with nested quantifiers
  (catastrophic-backtracking shape; rejected statically, never run);
- ``level_too_high`` — above ``LEARNED_MAX_LEVEL`` for a learned rule;
- ``empty_target`` — the target names no resolvable event;
- ``unknown_target_uid`` — none of the cited uids exist in either store;
- ``no_target_match`` — the rule matches no target event;
- ``baseline_match`` — the rule fires on the benign baseline.

Documented limits (chosen for the Linux lab data, fixed here):

- ``MAX_RULE_BYTES`` 1_000_000: a larger submission is refused unread.
- ``MAX_ALIASES`` 50 / ``MAX_ANCHORS`` 50 / ``MAX_INDENT_DEPTH`` 40:
  legitimate Sigma rules carry no YAML aliases and nest a handful of
  levels; beyond this is a bomb or nesting suspect.
- ``PARSE_TIMEOUT_S`` 15, ``EVAL_TIMEOUT_S`` 60: wall-clock caps so a
  hostile submission cannot hang the caller. DuckDB itself runs RE2
  (linear time, no backtracking), and nested-quantifier patterns are
  rejected before they ever reach it.
- ``MAX_EXCLUSIONS`` 1: at most one ``NOT`` in the executed SQL.
- ``MIN_LITERAL_LEN`` 4: substring/wildcard literals need at least 4
  effective characters (``curl`` passes, ``sh`` does not).
- ``MAX_CLASS_SHARE`` 0.05: a rule matching more than 5% of all events
  of its class across the baseline-plus-chain data is over-broad.
- ``LEARNED_MAX_LEVEL`` ``high``: a learned rule may not ship
  ``critical`` without a human writing it as such.
"""

from __future__ import annotations

import glob
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "ALL_CODES",
    "BacktestResult",
    "EVAL_TIMEOUT_S",
    "LEARNED_MAX_LEVEL",
    "MAX_ALIASES",
    "MAX_ANCHORS",
    "MAX_CLASS_SHARE",
    "MAX_EXCLUSIONS",
    "MAX_INDENT_DEPTH",
    "MAX_RULE_BYTES",
    "MIN_LITERAL_LEN",
    "PARSE_TIMEOUT_S",
    "backtest",
]

#: Refuse the submission unread above this many UTF-8 bytes.
MAX_RULE_BYTES = 1_000_000

#: Alias (``key: *name``) and anchor (``&name``) screens for YAML
#: entity-expansion suspects. Sigma rules have no legitimate use for
#: either; the counts below are far above zero yet far below a bomb.
MAX_ALIASES = 50
MAX_ANCHORS = 50

#: Indentation depth screen (two spaces per level). Real rules nest
#: detection selections a handful of levels; deeper is suspect.
MAX_INDENT_DEPTH = 40

#: Wall-clock budgets in seconds (worker-thread caps, never hangs).
PARSE_TIMEOUT_S = 15.0
EVAL_TIMEOUT_S = 60.0

#: At most one NOT in the executed SQL (counted outside literals).
MAX_EXCLUSIONS = 1

#: Substring/wildcard literals need this many effective characters.
MIN_LITERAL_LEN = 4

#: A rule matching more than this share of its class (baseline plus
#: chain) is over-broad.
MAX_CLASS_SHARE = 0.05

#: Ceiling level for a learned rule (``critical`` needs a human).
LEARNED_MAX_LEVEL = "high"

#: Baseline sample uids reported (sorted, never raw events).
BASELINE_SAMPLE_UIDS = 10

#: pySigma error text kept verbatim up to this many characters.
ERROR_CAP = 500

#: Sigma severity order (low to high).
LEVEL_ORDER = ("informational", "low", "medium", "high", "critical")

#: Every rejection code plus the success code, for tests to pin.
ALL_CODES = frozenset(
    {
        "accepted",
        "bad_input",
        "too_large",
        "yaml_bomb",
        "too_deep",
        "timeout",
        "parse_error",
        "rule_count",
        "unroutable",
        "unmapped_field",
        "unsupported_construct",
        "exclusion",
        "over_broad_literal",
        "leading_wildcard_regex",
        "dangerous_regex",
        "level_too_high",
        "empty_target",
        "unknown_target_uid",
        "no_target_match",
        "baseline_match",
        "over_broad_share",
    }
)


@dataclass
class BacktestResult:
    """The structured verdict for one candidate rule."""

    accepted: bool
    codes: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    rule_id: str | None = None
    title: str | None = None
    group: str | None = None
    target_matched: list[str] = field(default_factory=list)
    target_total: int = 0
    baseline_count: int = 0
    baseline_per_host: dict[str, int] = field(default_factory=dict)
    baseline_sample_uids: list[str] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)
    cost: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable verdict."""
        return {
            "accepted": self.accepted,
            "codes": list(self.codes),
            "detail": dict(self.detail),
            "rule_id": self.rule_id,
            "title": self.title,
            "group": self.group,
            "target_matched": list(self.target_matched),
            "target_total": self.target_total,
            "baseline_count": self.baseline_count,
            "baseline_per_host": dict(self.baseline_per_host),
            "baseline_sample_uids": list(self.baseline_sample_uids),
            "scope": dict(self.scope),
            "cost": dict(self.cost),
        }


def _fail(code: str, note: str) -> BacktestResult:
    """Build a single-code rejection (always well-formed)."""
    return BacktestResult(accepted=False, codes=[code], detail={"note": note})


def _run_with_timeout(func: Any, timeout_s: float) -> tuple[str, Any]:
    """Run ``func()`` in a worker thread.

    Returns ``("ok", value)``, ``("timeout", None)`` when the budget
    expires, or ``("error", exc)`` when the call raised. The three
    outcomes stay distinct so a parse failure is never reported as a
    timeout.
    """
    outcome: list[tuple[str, Any]] = []

    def _target() -> None:
        try:
            outcome.append(("ok", func()))
        except BaseException as exc:  # never raises out of backtest
            outcome.append(("error", exc))

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive() or not outcome:
        return "timeout", None
    status, value = outcome[0]
    return status, value


def _count_aliases(text: str) -> tuple[int, int]:
    """Count YAML alias uses (``key: *name``) and anchors (``&name``)."""
    aliases = len(re.findall(r":\s*\*[A-Za-z0-9_-]+", text))
    anchors = len(re.findall(r"&\S+", text))
    return aliases, anchors


def _max_indent_depth(text: str) -> int:
    """Return the deepest leading-indent level (tabs count as 8)."""
    deepest = 0
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        indent = line[: len(line) - len(stripped)]
        width = sum(8 if char == "\t" else 1 for char in indent)
        deepest = max(deepest, width // 2)
    return deepest


def _strip_string_literals(sql: str) -> str:
    """Remove single-quoted literals so keywords inside values hide."""
    out: list[str] = []
    index = 0
    size = len(sql)
    while index < size:
        char = sql[index]
        if char == "'":
            end = index + 1
            while end < size:
                if sql[end] == "'":
                    if sql[end + 1 : end + 2] == "'":
                        end += 2
                        continue
                    break
                end += 1
            index = end + 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _count_negations(sql: str) -> int:
    """Count ``NOT`` operators outside string literals."""
    return len(re.findall(r"\bNOT\b", _strip_string_literals(sql)))


_SUBSTRING_MODIFIERS = frozenset(
    {"SigmaContainsModifier", "SigmaStartswithModifier", "SigmaEndswithModifier"}
)


def _sigma_text_parts(value: Any) -> str:
    """Render the literal characters of a SigmaString (no wildcards)."""
    parts = getattr(value, "s", None)
    if parts is None:
        return str(value)
    return "".join(str(part) for part in parts if isinstance(part, str))


def _sigma_pattern(value: Any) -> str:
    """Reconstruct a ``|re`` pattern with Sigma wildcards restored.

    A ``SigmaString`` splits ``*``/``?`` into ``SpecialChars`` marks;
    without restoring them a leading ``.*`` would read as ``..`` and
    the leading-wildcard screen would miss it.
    """
    from sigma.types import SpecialChars

    parts = getattr(value, "s", None)
    if parts is None:
        return str(value)
    out: list[str] = []
    for part in parts:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append("*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append("?")
        else:
            out.append(str(part))
    return "".join(out)


def _iter_leaf_items(node: Any) -> Any:
    """Yield every leaf detection item under a detection tree."""
    children = getattr(node, "detection_items", None)
    if not children:
        return
    for child in children:
        nested = getattr(child, "detection_items", None)
        if nested:
            yield from _iter_leaf_items(child)
        else:
            yield child


def _modifier_names(modifiers: Any) -> set[str]:
    """Return modifier names (pySigma stores classes, not instances)."""
    names = set()
    for mod in modifiers or []:
        names.add(mod.__name__ if isinstance(mod, type) else type(mod).__name__)
    return names


def _check_literals(rule: Any) -> str | None:
    """Reject short substring literals; None when all pass."""
    for detection in rule.detection.detections.values():
        for item in _iter_leaf_items(detection):
            names = _modifier_names(item.modifiers)
            if names & _SUBSTRING_MODIFIERS:
                values = item.value if isinstance(item.value, list) else [item.value]
                for value in values:
                    literal = _sigma_text_parts(value)
                    if len(literal) < MIN_LITERAL_LEN:
                        return (
                            f"{item.field} literal {literal!r} "
                            f"shorter than {MIN_LITERAL_LEN}"
                        )
    return None


_NESTED_QUANTIFIER = re.compile(
    r"(\([^()]*[+*][^()]*\))[+*?]|(\[[^\]]*[+*][^\]]*\])[+*?]"
)


def _check_regexes(rule: Any) -> str | None:
    """Reject leading-wildcard and nested-quantifier patterns.

    Returns the rejection code (``leading_wildcard_regex`` or
    ``dangerous_regex``) with the pattern in the detail note, or None.
    """
    for detection in rule.detection.detections.values():
        for item in _iter_leaf_items(detection):
            names = _modifier_names(item.modifiers)
            if "SigmaRegularExpressionModifier" not in names:
                continue
            values = item.value if isinstance(item.value, list) else [item.value]
            for value in values:
                pattern = _sigma_pattern(getattr(value, "regexp", value))
                if pattern.startswith(".*") or pattern.startswith(".+"):
                    return f"leading_wildcard_regex:{pattern[:80]}"
                if _NESTED_QUANTIFIER.search(pattern):
                    return f"dangerous_regex:{pattern[:80]}"
    return None


def _parse_moment(value: Any) -> int | None:
    """Parse an ISO-8601 instant or epoch milliseconds; None when bad."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return int(moment.timestamp() * 1000)
    return None


def _store_uid_index(replay_dir: str | Path) -> dict[str, tuple[str, int]]:
    """Map every event uid in the store to ``(host, time)``."""
    index: dict[str, tuple[str, int]] = {}
    for path in sorted(glob.glob(str(Path(replay_dir) / "events" / "*.parquet"))):
        import pyarrow.parquet as pq

        for row in pq.read_table(path, columns=["uid", "host", "time"]).to_pylist():
            uid = row.get("uid")
            if isinstance(uid, str):
                index[uid] = (str(row.get("host")), int(row.get("time")))
    return index


def _store_class_count(replay_dir: str | Path, class_uid: int) -> int:
    """Count events of one OCSF class in the store (flat column)."""
    total = 0
    for path in sorted(glob.glob(str(Path(replay_dir) / "events" / "*.parquet"))):
        import pyarrow.parquet as pq

        column = pq.read_table(path, columns=["class_uid"]).column("class_uid")
        total += sum(1 for value in column.to_pylist() if value == class_uid)
    return total


def _store_host_window(
    replay_dir: str | Path, host: str, start_ms: int, end_ms: int
) -> dict[str, tuple[str, int]]:
    """Map uids of one host's events inside ``[start, end]``."""
    found: dict[str, tuple[str, int]] = {}
    for path in sorted(glob.glob(str(Path(replay_dir) / "events" / "*.parquet"))):
        import pyarrow.parquet as pq

        for row in pq.read_table(path, columns=["uid", "host", "time"]).to_pylist():
            uid = row.get("uid")
            moment = row.get("time")
            if (
                isinstance(uid, str)
                and row.get("host") == host
                and isinstance(moment, int)
                and start_ms <= moment <= end_ms
            ):
                found[uid] = (str(row.get("host")), int(moment))
    return found


def backtest(
    sigma_text: Any,
    target: Any,
    *,
    baseline_dir: str | Path = "data/replay-linux-baseline",
    chain_dir: str | Path = "data/replay-linux-chain1",
) -> BacktestResult:
    """Backtest one candidate Sigma rule against a target; never raises."""
    try:
        return _backtest_inner(
            sigma_text, target, baseline_dir=baseline_dir, chain_dir=chain_dir
        )
    except Exception as exc:  # never raises on bad input
        return BacktestResult(
            accepted=False,
            codes=["bad_input"],
            detail={"note": f"{type(exc).__name__}: {str(exc)[:ERROR_CAP]}"},
        )


def _backtest_inner(
    sigma_text: Any,
    target: Any,
    *,
    baseline_dir: str | Path,
    chain_dir: str | Path,
) -> BacktestResult:
    started = time.monotonic()
    if not isinstance(sigma_text, str) or not sigma_text.strip():
        return _fail("bad_input", "sigma_text must be a non-empty string")
    if len(sigma_text.encode("utf-8")) > MAX_RULE_BYTES:
        return _fail(
            "too_large",
            f"rule exceeds {MAX_RULE_BYTES} bytes",
        )
    aliases, anchors = _count_aliases(sigma_text)
    if aliases > MAX_ALIASES or anchors > MAX_ANCHORS:
        return _fail(
            "yaml_bomb",
            f"aliases={aliases} anchors={anchors} above the screen",
        )
    if _max_indent_depth(sigma_text) > MAX_INDENT_DEPTH:
        return _fail("too_deep", "indentation deeper than the screen")
    if not isinstance(target, dict):
        return _fail("bad_input", "target must be a mapping")

    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule

    status, parsed = _run_with_timeout(
        lambda: SigmaCollection.from_yaml(sigma_text), PARSE_TIMEOUT_S
    )
    if status == "timeout":
        return _fail("timeout", f"parse exceeded {PARSE_TIMEOUT_S} s")
    if status == "error":
        message = str(parsed) if str(parsed).strip() else repr(parsed)
        return _fail("parse_error", f"{type(parsed).__name__}: {message}"[:ERROR_CAP])
    if not isinstance(parsed, SigmaCollection):
        return _fail("parse_error", f"unexpected parse result: {parsed!r}"[:ERROR_CAP])

    plain = [
        rule for rule in parsed.rules if not isinstance(rule, SigmaCorrelationRule)
    ]
    if len(parsed.rules) != len(plain):
        return _fail("unsupported_construct", "correlation rule")
    if len(plain) != 1:
        return _fail("rule_count", f"expected 1 rule, found {len(plain)}")
    rule = plain[0]

    literal_note = _check_literals(rule)
    if literal_note is not None:
        return _fail("over_broad_literal", literal_note)
    regex_hit = _check_regexes(rule)
    if regex_hit is not None:
        code, _, note = regex_hit.partition(":")
        return _fail(code, note)

    from corvus.detect.rules import ALL_STATUSES, load_rules

    with tempfile.TemporaryDirectory(prefix="candidate") as tmp:
        candidate = Path(tmp) / "candidate.yml"
        candidate.write_text(sigma_text, encoding="utf-8")
        try:
            compiled, stats = load_rules(candidate.parent, statuses=ALL_STATUSES)
        except Exception as exc:
            return _fail(
                "unsupported_construct",
                f"{type(exc).__name__}: {str(exc)[:ERROR_CAP]}",
            )
    if len(compiled) != 1:
        return _skip_to_code(stats)
    item = compiled[0]

    level = str(item.level).lower()
    if level not in LEVEL_ORDER:
        return _fail("unsupported_construct", f"unknown level: {item.level}")
    if LEVEL_ORDER.index(level) > LEVEL_ORDER.index(LEARNED_MAX_LEVEL):
        return _fail(
            "level_too_high",
            f"level {level} above the learned-rule ceiling {LEARNED_MAX_LEVEL}",
        )

    if _count_negations(item.sql) > MAX_EXCLUSIONS:
        return _fail(
            "exclusion",
            f"more than {MAX_EXCLUSIONS} negation in the executed SQL",
        )

    resolved = _resolve_target(target, chain_dir, baseline_dir)
    if resolved is None:
        return _fail("bad_input", "malformed target")
    wanted, unknown, scope = resolved
    if not wanted:
        code = "unknown_target_uid" if unknown else "empty_target"
        return _fail(code, scope.get("note", "no resolvable target event"))

    from corvus.detect.engine import evaluate

    eval_started = time.monotonic()

    def _run_both() -> Any:
        chain_matches, _, chain_stats = evaluate(chain_dir, [item])
        base_matches, _, base_stats = evaluate(baseline_dir, [item])
        return chain_matches, chain_stats, base_matches, base_stats

    status, result = _run_with_timeout(_run_both, EVAL_TIMEOUT_S)
    if status == "timeout":
        return _fail("timeout", f"evaluation exceeded {EVAL_TIMEOUT_S} s")
    if status == "error" or not isinstance(result, tuple):
        note = (
            f"{type(result).__name__}: {str(result)[:ERROR_CAP]}"
            if status == "error"
            else f"unexpected evaluation result: {result!r}"[:ERROR_CAP]
        )
        return _fail("unsupported_construct", note)
    chain_matches, chain_stats, base_matches, base_stats = result
    eval_ms = (time.monotonic() - eval_started) * 1000

    matched_chain = set(chain_matches.get(item.rule_id, set()))
    matched_base = set(base_matches.get(item.rule_id, set()))
    target_set = set(wanted)
    target_matched = sorted((matched_chain | matched_base) & target_set)
    baseline_hits = sorted(matched_base - target_set)

    from corvus.detect.mapping import GROUPS

    group = GROUPS[item.group]
    class_total = sum(
        _store_class_count(baseline_dir, uid) + _store_class_count(chain_dir, uid)
        for uid in group.class_uids
    )
    matched_total = len(matched_chain | matched_base)
    share = (matched_total / class_total) if class_total else 0.0
    if share > MAX_CLASS_SHARE:
        return _share_fail(matched_total, class_total, share)

    codes: list[str] = []
    detail: dict[str, Any] = {}
    if unknown:
        detail["unknown_uids"] = sorted(unknown)
    if not target_matched:
        codes.append("no_target_match")
    if baseline_hits:
        codes.append("baseline_match")

    baseline_index = _store_uid_index(baseline_dir)
    per_host: dict[str, int] = {}
    for uid in baseline_hits:
        host = baseline_index.get(uid, ("unknown", 0))[0]
        per_host[host] = per_host.get(host, 0) + 1

    cost = {
        "rows_scanned": int(chain_stats.events_scanned + base_stats.events_scanned),
        "milliseconds": round(eval_ms, 1),
    }
    verdict = BacktestResult(
        accepted=not codes,
        codes=["accepted"] if not codes else codes,
        detail=detail,
        rule_id=item.rule_id,
        title=item.title,
        group=item.group,
        target_matched=target_matched,
        target_total=len(target_set),
        baseline_count=len(baseline_hits),
        baseline_per_host=per_host,
        baseline_sample_uids=baseline_hits[:BASELINE_SAMPLE_UIDS],
        scope=scope,
        cost=cost,
    )
    _ = time.monotonic() - started
    return verdict


def _share_fail(matched_total: int, class_total: int, share: float) -> BacktestResult:
    """Build the over-broad share rejection (code registered below)."""
    return BacktestResult(
        accepted=False,
        codes=["over_broad_share"],
        detail={
            "note": (
                f"matched {matched_total} of {class_total} class events "
                f"(share {share:.3f} above {MAX_CLASS_SHARE})"
            )
        },
    )


def _skip_to_code(stats: Any) -> BacktestResult:
    """Map a load skip (no compiled rule) to its stable rejection code."""
    for reason, bucket in (stats.skip_details or {}).items():
        first = sorted(bucket)[0] if bucket else ""
        if reason == "logsource":
            return _fail("unroutable", first)
        if reason == "event_id":
            return _fail("unroutable", first)
        if reason == "unmapped_field":
            return _fail("unmapped_field", first)
        return _fail("unsupported_construct", first or reason)
    return _fail("unsupported_construct", "rule did not compile")


def _resolve_target(
    target: dict[str, Any], chain_dir: str | Path, baseline_dir: str | Path
) -> tuple[list[str], list[str], dict[str, Any]] | None:
    """Resolve the target to ``(wanted, unknown, scope)``; None when malformed.

    The scope names the hosts, the event count, and the time spread of
    the resolved target events.
    """
    index: dict[str, tuple[str, int]] = {}
    if "event_uids" in target:
        uids = target["event_uids"]
        if not isinstance(uids, list) or not uids:
            return (
                [],
                [],
                {
                    "note": "empty uid target",
                    "hosts": [],
                    "event_count": 0,
                    "time_spread_ms": None,
                },
            )
        if any(not isinstance(uid, str) for uid in uids):
            return None
        index = _store_uid_index(chain_dir)
        index.update(
            {
                uid: mark
                for uid, mark in _store_uid_index(baseline_dir).items()
                if uid not in index
            }
        )
        seen: set[str] = set()
        wanted = []
        for uid in uids:
            if uid in index and uid not in seen:
                seen.add(uid)
                wanted.append(uid)
        unknown = [uid for uid in uids if uid not in index]
        note = f"{len(wanted)} of {len(uids)} cited uids resolve"
    elif "host" in target or "start" in target or "end" in target:
        host = target.get("host")
        start = _parse_moment(target.get("start"))
        end = _parse_moment(target.get("end"))
        if not isinstance(host, str) or not host or start is None or end is None:
            return None
        if end < start:
            return None
        found = _store_host_window(chain_dir, host, start, end)
        wanted = sorted(found)
        unknown = []
        index = found
        note = f"host {host} window {start}..{end}"
    else:
        return (
            [],
            [],
            {
                "note": "target names no resolvable event",
                "hosts": [],
                "event_count": 0,
                "time_spread_ms": None,
            },
        )
    hosts = sorted({index[uid][0] for uid in wanted})
    moments = [index[uid][1] for uid in wanted]
    spread = (max(moments) - min(moments)) if moments else None
    return (
        wanted,
        unknown,
        {
            "note": note,
            "hosts": hosts,
            "event_count": len(wanted),
            "time_spread_ms": spread,
        },
    )
