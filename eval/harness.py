"""Eval harness: one command measuring the product code paths.

``corvus eval run`` runs load (inventory of the replay store built by
``corvus replay load``) -> detect (``corvus.detect.load_rules`` +
``corvus.detect.engine.evaluate`` + ``write_findings``, the same calls
``corvus replay detect`` makes) -> correlate
(``corvus.correlate.replay.correlate_replay_store``, the same call
``corvus correlate replay`` makes before the database write) and writes
``eval/reports/latest.md`` plus ``eval/reports/latest.json``.

Every number carries its ``n``, the data window, the producing command
and the git commit (see ``meta`` in the JSON and the header of the
markdown). The benign set is generated with ``eval.benign_windows``
and split with ``eval.train_test_split``; both are used, never
rewritten. Detection and correlation are never reimplemented here:
metric joins read the findings and incidents the product code wrote.

Gates (a failing gate exits 1 and fails the run):

- benign false positives: zero incidents with severity ``Critical``
  (``severity_id`` 5) or ``Fatal`` (6) on the synthetic benign set;
  ``High`` and below are reported, never tuned away silently.
- anti-leakage: no dataset name, file name, ground-truth technique id
  or chain anchor reaches an OCSF event, finding or incident row,
  except rule tags in findings (detector output) and rows the loader
  flagged in-band (reported under the in-band metric instead). The
  string logic reuses ``find_technique_ids`` and the assertions of
  ``tests/test_replay.py`` and ``tests/test_chain_ground_truth.py``.

Deltas: ``latest.json`` is committed; each run compares the fresh
results against the committed file and prints the metric deltas. When
the inputs differ (rule set, dataset pins, generator seed, correlation
settings) the harness says so instead of reporting a misleading delta.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT))

DEFAULT_REPLAY_DIR = REPO_ROOT / "data" / "replay"
DEFAULT_ATTACK_PATH = REPO_ROOT / "data" / "attack" / "enterprise.json"
DEFAULT_GROUND_TRUTH = REPO_ROOT / "data" / "ground_truth.json"
DEFAULT_RULES_DIR = REPO_ROOT / "data" / "sigma" / "rules"
DEFAULT_REPORT_MD = REPO_ROOT / "eval" / "reports" / "latest.md"
DEFAULT_REPORT_JSON = REPO_ROOT / "eval" / "reports" / "latest.json"

BENIGN_HOSTS = 4
BENIGN_HOURS = 24
BENIGN_SEED = 7

SEVERITY_IDS = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

ID_TO_NAME = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}

OTRF_METADATA_SOURCE = "otrf-metadata"


def git_commit() -> str:
    """Return the current HEAD commit, or ``unknown`` off-repo."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError, subprocess.SubprocessError:
        return "unknown"
    commit = out.stdout.strip()
    return commit if commit else "unknown"


def maintainer_today() -> str:
    """Return today's date in the maintainer's local date (UTC-6)."""
    return (datetime.now(tz=UTC) - timedelta(hours=6)).date().isoformat()


def parse_ms(moment: str) -> int:
    """Parse an ISO-8601 UTC moment to epoch milliseconds."""
    parsed = datetime.fromisoformat(moment.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def format_ms(moment_ms: int) -> str:
    """Format epoch milliseconds as an ISO-8601 UTC moment."""
    return (
        datetime.fromtimestamp(moment_ms / 1000, tz=UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha_of_file(path: Path) -> str:
    """Return the hex SHA-256 of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def benign_gate_fails(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the incidents tripping the benign gate (severity >= Critical).

    The gate is zero incidents at ``severity_id`` 5 (Critical) or above
    on the synthetic benign set. ``High`` (4) and below are reported in
    the tables, never silently tolerated.
    """
    return [
        incident
        for incident in incidents
        if int(incident.get("severity_id", 0)) >= SEVERITY_IDS["critical"]
    ]


def check_leakage(
    dumps: list[str],
    forbidden_substrings: list[str],
    forbidden_ids: list[str],
    *,
    check_techniques: bool = True,
) -> list[str]:
    """Scan serialized rows for ground-truth leakage (pure, testable).

    Mirrors the assertions of ``tests/test_replay.py`` (file names and
    technique ids never reach adapter returns) and
    ``tests/test_chain_ground_truth.py`` (dataset, technique, anchor and
    window strings never reach records): every dump must contain none
    of the forbidden substrings (case-insensitive) and, when
    ``check_techniques`` holds, none of the forbidden technique ids,
    with ``find_technique_ids`` over the dump empty. Callers choose
    which markers to pass: dataset/file/window markers for every store,
    chain anchors only for the synthetic benign store (anchors are real
    attack evidence in the attack store — the chain census counts anchor
    hits in mapped events — so only the benign probe can fail on them).
    Callers also scrub detector output (finding attacks, incident
    techniques) and exempt loader-flagged in-band rows before calling.
    Returns the hit descriptions (empty when clean).
    """
    from corvus.normalize.technique_ids import find_technique_ids

    hits: list[str] = []
    for index, dump in enumerate(dumps):
        lowered = dump.lower()
        for marker in forbidden_substrings:
            if marker and marker.lower() in lowered:
                hits.append(f"row {index}: forbidden substring {marker!r}")
        if not check_techniques:
            continue
        for technique in forbidden_ids:
            if technique and technique in dump:
                hits.append(f"row {index}: forbidden technique id {technique!r}")
        if find_technique_ids(dump):
            hits.append(f"row {index}: technique token {find_technique_ids(dump)!r}")
    return hits


def inventory_store(replay_dir: Path) -> dict[str, Any]:
    """Inventory the replay store without re-running the loader.

    Reads Parquet metadata and the small columns (``time`` for the
    window, provenance ``file``/``dataset``/``in_band_technique_id``
    for the join) file by file, so the full store is never held in
    memory. Returns event totals, per-dataset counts, the data window,
    the distinct files, per-file in-band flags and the row counts the
    ``n`` values below reproduce from.
    """
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import events_dir, provenance_dir

    events_path = events_dir(replay_dir)
    prov_path = provenance_dir(replay_dir)
    if not events_path.is_dir():
        raise FileNotFoundError(f"replay events missing: {events_path}")
    event_files = sorted(events_path.glob("*.parquet"))
    if not event_files:
        raise FileNotFoundError(f"no event files under {events_path}")
    events_total = 0
    window_start: int | None = None
    window_end: int | None = None
    for path in event_files:
        meta = pq.read_metadata(path)
        events_total += meta.num_rows
        times = pq.read_table(path, columns=["time"]).column("time").to_pylist()
        if times:
            low, high = min(times), max(times)
            window_start = low if window_start is None else min(window_start, low)
            window_end = high if window_end is None else max(window_end, high)
    prov_files = sorted(prov_path.glob("*.parquet")) if prov_path.is_dir() else []
    file_to_dataset: dict[str, str] = {}
    file_in_band: dict[str, bool] = {}
    dataset_events: Counter[str] = Counter()
    dataset_files: Counter[str] = Counter()
    in_band_events = 0
    if prov_files:
        import pyarrow.compute as pc

        for path in prov_files:
            table = pq.read_table(
                path, columns=["file", "dataset", "in_band_technique_id"]
            )
            files = table.column("file").to_pylist()
            if not files:
                continue
            data_file = str(files[0])
            dataset = str(table.column("dataset").to_pylist()[0])
            file_to_dataset[data_file] = dataset
            flagged = pc.sum(table.column("in_band_technique_id")).as_py() or 0
            file_in_band[data_file] = bool(flagged)
            in_band_events += int(flagged)
            dataset_files[dataset] += 1
        from corvus.adapters.replay.schema import slug_for_rel

        slug_to_file = {slug_for_rel(rel): rel for rel in file_to_dataset}
        for path in event_files:
            rel = slug_to_file.get(path.stem)
            if rel is not None:
                dataset_events[file_to_dataset[rel]] += pq.read_metadata(path).num_rows
    return {
        "events_total": events_total,
        "event_files": len(event_files),
        "window_start": window_start,
        "window_end": window_end,
        "file_to_dataset": file_to_dataset,
        "file_in_band": file_in_band,
        "dataset_events": dict(sorted(dataset_events.items())),
        "dataset_files": dict(sorted(dataset_files.items())),
        "in_band_events": in_band_events,
    }


def load_finding_rows(
    replay_dir: Path, attack: Any, uid_to_file: dict[str, str]
) -> list[dict[str, Any]]:
    """Read stored findings into light rows (no event content).

    Each row carries the finding uid, time, rule, level, host, the
    data-relative file of its related event, and the parent-expanded
    technique set. Technique expansion matches ``eval/detect_census.py``
    (parent or self on both sides); the join only reads what the
    product detector wrote.
    """
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import findings_dir
    from corvus.attack import normalize_id

    directory = findings_dir(replay_dir)
    rows: list[dict[str, Any]] = []
    if not directory.is_dir():
        return rows

    def expanded(techniques: list[str]) -> set[str]:
        out: set[str] = set()
        for raw in techniques:
            canonical = normalize_id(raw) or raw
            out.add(canonical)
            entry = attack.resolve(canonical)
            if entry is not None and entry.is_subtechnique and entry.parent:
                out.add(entry.parent)
        return out

    for path in sorted(directory.glob("*.parquet")):
        for record in pq.read_table(path).to_pylist():
            finding = json.loads(str(record["finding_json"]))
            info = finding.get("finding_info") or {}
            techniques: set[str] = set()
            for item in info.get("attacks") or []:
                sub = (item.get("sub_technique") or {}).get("uid")
                tech = (item.get("technique") or {}).get("uid")
                if sub or tech:
                    techniques.add(str(sub or tech))
            related = ""
            for related_event in info.get("related_events") or []:
                if related_event.get("uid"):
                    related = str(related_event["uid"])
                    break
            rows.append(
                {
                    "uid": str(record["uid"]),
                    "time": int(record["time"]),
                    "rule_id": str(record["rule_id"]),
                    "level": str(record["level"]),
                    "host": str(record.get("host") or ""),
                    "file": uid_to_file.get(related, ""),
                    "techniques": expanded(sorted(techniques)),
                    "finding_json": str(record["finding_json"]),
                }
            )
    return rows


def discover_chains() -> list[dict[str, Any]]:
    """Load every committed chain-level ground truth file.

    Today that is APT29 day-1; the Linux chain and its variant join
    later as files appear, and discovery picks them up without a code
    change. Files without ``label_level == "chain"`` are ignored.
    """
    chains: list[dict[str, Any]] = []
    for path in sorted((REPO_ROOT / "eval").glob("*ground_truth.json")):
        try:
            chain = json.loads(path.read_text(encoding="utf-8"))
        except OSError, ValueError:
            continue
        if isinstance(chain, dict) and chain.get("label_level") == "chain":
            chain["_path"] = path.name
            chains.append(chain)
    return chains


def chain_step_coverage(
    chain: dict[str, Any],
    finding_rows: list[dict[str, Any]],
    incident_member_uids: list[set[str]],
    attack: Any,
) -> dict[str, Any]:
    """Cover each chain step with the best incident and with all incidents.

    A step is covered by an incident when the incident holds a finding
    from the chain file inside the step window whose parent-expanded
    technique set meets the step's parent-expanded techniques. Windows
    and techniques come from the chain file; the join mirrors
    ``eval/correlate_census.py``. Never a lone boolean: the report
    carries per-step coverage for the best incident and for all
    incidents together.
    """
    from corvus.attack import normalize_id

    def ground_expanded(techniques: list[Any]) -> set[str]:
        out: set[str] = set()
        for raw in techniques:
            canonical = normalize_id(str(raw)) or str(raw)
            out.add(canonical)
            entry = attack.resolve(canonical)
            if entry is not None and entry.is_subtechnique and entry.parent:
                out.add(entry.parent)
        return out

    chain_file = str(chain.get("dataset_file", ""))
    steps: list[dict[str, Any]] = []
    for step in chain.get("steps", []):
        window = step.get("window", {})
        start = parse_ms(window["start"])
        end = parse_ms(window["end"])
        steps.append(
            {
                "step": int(step["step"]),
                "name": str(step["name"]),
                "window": dict(window),
                "techniques": list(step["techniques"]),
                "ground": ground_expanded(list(step["techniques"])),
                "start": start,
                "end": end,
            }
        )
    per_incident: list[list[int]] = []
    for members in incident_member_uids:
        covered: list[int] = []
        for step in steps:
            hit = any(
                row["file"] == chain_file
                and step["start"] <= row["time"] <= step["end"]
                and bool(row["techniques"] & step["ground"])
                for row in finding_rows
                if row["uid"] in members
            )
            if hit:
                covered.append(step["step"])
        per_incident.append(covered)
    all_covered = sorted({step_no for covered in per_incident for step_no in covered})
    best: list[int] = []
    best_index = -1
    for index, covered in enumerate(per_incident):
        if (len(covered), len(incident_member_uids[index])) > (
            len(best),
            len(incident_member_uids[best_index]) if best_index >= 0 else -1,
        ):
            best = covered
            best_index = index
    return {
        "chain_id": str(chain.get("chain_id", "")),
        "dataset_file": chain_file,
        "window": dict(chain.get("window", {})),
        "steps": [
            {
                "step": step["step"],
                "name": step["name"],
                "window": step["window"],
                "techniques": step["techniques"],
                "covered_by_best": step["step"] in best,
                "covered_by_all": step["step"] in all_covered,
            }
            for step in steps
        ],
        "best_covered_n": len(best),
        "all_covered_n": len(all_covered),
        "steps_n": len(steps),
    }


def atomic_coverage(
    ground_truth: dict[str, Any],
    finding_rows: list[dict[str, Any]],
    store_files: set[str],
) -> dict[str, Any]:
    """OTRF ``otrf-metadata`` files with a technique-matching finding.

    A file counts as matched when at least one of its findings carries
    a technique whose parent (or self) is one of the file's ground-truth
    techniques. Files with no events in the replay store (network/pcap
    datasets, never ingested) are reported separately instead of being
    counted as misses. The parent-or-self comparison matches
    ``eval/detect_census.py``.
    """
    from corvus.attack import normalize_id

    def expanded(techniques: list[Any]) -> set[str]:
        out: set[str] = set()
        for raw in techniques:
            canonical = normalize_id(str(raw)) or str(raw)
            out.add(canonical)
            out.add(canonical.split(".")[0])
        return out

    truth_files = sorted(
        key
        for key, label in ground_truth.items()
        if isinstance(label, dict)
        and label.get("label_source") == OTRF_METADATA_SOURCE
        and label.get("techniques")
    )
    in_store = [key for key in truth_files if key in store_files]
    not_in_store = [key for key in truth_files if key not in store_files]
    by_file: dict[str, list[dict[str, Any]]] = {}
    for row in finding_rows:
        by_file.setdefault(row["file"], []).append(row)
    per_file = []
    with_finding = 0
    with_match = 0
    for data_file in in_store:
        rows = by_file.get(data_file, [])
        ground = expanded(list(ground_truth[data_file].get("techniques", [])))
        matched = sorted(
            {
                technique
                for row in rows
                for technique in row["techniques"]
                if technique in ground
            }
        )
        if rows:
            with_finding += 1
        if matched:
            with_match += 1
        per_file.append(
            {
                "file": data_file,
                "findings_n": len(rows),
                "matched": bool(matched),
                "matched_techniques": matched,
            }
        )
    return {
        "files_with_ground_truth_n": len(truth_files),
        "in_store_n": len(in_store),
        "not_in_store_n": len(not_in_store),
        "not_in_store": not_in_store,
        "with_finding_n": with_finding,
        "with_match_n": with_match,
        "per_file": per_file,
    }


def run_detect(replay_dir: Path, rules_dir: Path, attack: Any) -> dict[str, Any]:
    """Run the product detector over one replay store (same calls as the CLI).

    Calls ``corvus.detect.load_rules``, ``corvus.detect.engine.evaluate``
    and ``write_findings`` exactly as ``corvus replay detect`` does, so
    the harness measures the shipped code instead of a copy of it.
    """
    from corvus.adapters.replay.findings import write_findings
    from corvus.detect import load_rules
    from corvus.detect.engine import evaluate

    attack_path = REPO_ROOT / "data" / "attack" / "enterprise.json"
    with open(attack_path, encoding="utf-8") as handle:
        attack_version = str(
            json.loads(handle.read()).get("attack_version", "v20.0")
        ).removeprefix("v")
    detect_started = time.monotonic()
    compiled, load_stats = load_rules(rules_dir)
    matches, _infos, eval_stats = evaluate(replay_dir, compiled)
    write_summary = write_findings(
        replay_dir, compiled, matches, _infos, attack, attack_version
    )
    return {
        "rules_files": load_stats.files,
        "rules_parsed": load_stats.parsed_rules,
        "rules_evaluated": len(compiled),
        "rules_skipped": dict(load_stats.skipped),
        "rules_errored_n": len(eval_stats.rules_errored),
        "matches": sum(len(uids) for uids in matches.values()),
        "findings": write_summary.findings,
        "events_scanned": eval_stats.events_scanned,
        "events_matched": eval_stats.events_matched,
        "seconds": round(time.monotonic() - detect_started, 1),
        "peak_rss_mb": round(eval_stats.peak_rss_mb, 0),
    }


def run_benign_pipeline(
    hosts: int, hours: int, seed: int, attack: Any, rules_dir: Path
) -> tuple[dict[str, Any], list[Any]]:
    """Generate, load, detect and correlate the synthetic benign set.

    Uses ``eval.benign_windows.generate`` (never rewritten here), loads
    the bundle with ``corvus.adapters.replay.load_path`` into a fresh
    git-ignored replay dir, then runs the same detect and correlate
    calls as the main pipeline. Everything is declared synthetic in the
    report. Returns the report summary plus the incidents (for the
    leakage probe; only counts land in the reports).
    """
    from corvus.adapters.replay import load_path
    from corvus.correlate.replay import correlate_replay_store
    from eval.benign_windows import bundle_name, generate, write_bundle

    benign_dir = REPO_ROOT / "data" / "benign"
    benign_dir.mkdir(parents=True, exist_ok=True)
    bundle = benign_dir / bundle_name(hosts=hosts, hours=hours, seed=seed)
    records = generate(seed=seed, hosts=hosts, hours=hours)
    write_bundle(records, bundle)
    replay_dir = REPO_ROOT / "data" / ".harness-benign-replay"
    if replay_dir.exists():
        shutil.rmtree(replay_dir)
    summary = load_path(bundle, replay_dir=replay_dir, data_dir=REPO_ROOT / "data")
    detect = run_detect(replay_dir, rules_dir, attack)
    incidents = correlate_replay_store(
        replay_dir=replay_dir,
        attack_path=DEFAULT_ATTACK_PATH,
        settings=_correlation_settings(),
        attack=attack,
    )
    by_severity: Counter[int] = Counter(
        int(incident["severity_id"]) for incident in incidents
    )
    summary_out = {
        "synthetic": True,
        "hosts": hosts,
        "hours": hours,
        "seed": seed,
        "records_n": len(records),
        "events_n": summary.events_total,
        "unmapped_n": sum(summary.unmapped.values()),
        "findings_n": detect["findings"],
        "incidents_n": len(incidents),
        "by_severity": {
            str(level): by_severity.get(level, 0) for level in (1, 2, 3, 4, 5, 6)
        },
        "tripping": [
            {
                "correlation_key": incident["correlation_key"],
                "severity_id": incident["severity_id"],
                "severity_floor": incident["severity_floor"],
            }
            for incident in benign_gate_fails(
                [dict(incident) for incident in incidents]
            )
        ],
        "replay_dir": str(replay_dir.relative_to(REPO_ROOT)),
    }
    return summary_out, incidents


def _uid_to_file(replay_dir: Path, wanted: set[str]) -> dict[str, str]:
    """Map the wanted event uids to their data-relative files.

    Streams the provenance tables file by file and keeps only the
    wanted uids, so the full 798k-row join is never held in memory.
    """
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import provenance_dir

    directory = provenance_dir(replay_dir)
    mapping: dict[str, str] = {}
    if not directory.is_dir() or not wanted:
        return mapping
    remaining = set(wanted)
    for path in sorted(directory.glob("*.parquet")):
        table = pq.read_table(path, columns=["uid", "file"])
        for record in table.to_pylist():
            uid = str(record["uid"])
            if uid in remaining and uid not in mapping:
                mapping[uid] = str(record["file"])
                remaining.discard(uid)
        if not remaining:
            break
    return mapping


def _split_record(ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Record the OTRF train/test split (uses, never rewrites, the splitter)."""
    from eval.train_test_split import otrf_files_by_technique, split_technique_files

    grouped = otrf_files_by_technique(ground_truth)
    split = split_technique_files(grouped)
    testable = [e for e in split.techniques.values() if not e.untestable]
    untestable = [e for e in split.techniques.values() if e.untestable]
    return {
        "techniques_n": len(split.techniques),
        "testable_n": len(testable),
        "untestable_n": len(untestable),
        "per_technique": {
            technique: {
                "train_n": len(entry.train),
                "test_n": len(entry.test),
                "untestable": entry.untestable,
            }
            for technique, entry in sorted(split.techniques.items())
        },
        "multi_label_files_n": len(split.multi_label_files),
        "multi_label_files": split.multi_label_files,
        "excluded": {key: len(files) for key, files in sorted(split.excluded.items())},
    }


def _compression(
    main_store: dict[str, Any],
    detect_stats: dict[str, Any],
    incidents: list[Any],
    finding_rows: list[dict[str, Any]],
    benign: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compress events -> findings -> incidents per dataset scope."""
    member_files: dict[str, set[str]] = {}
    for incident in incidents:
        files = {
            row["file"]
            for row in finding_rows
            if row["uid"] in set(incident["event_uids"]) and row["file"]
        }
        member_files[incident["correlation_key"]] = files
    scopes: list[dict[str, Any]] = [
        {
            "scope": "whole store",
            "events_n": main_store["events_total"],
            "findings_n": detect_stats["findings"],
            "incidents_n": len(incidents),
        }
    ]
    for dataset in sorted(main_store["dataset_events"]):
        files = {
            rel
            for rel, owner in main_store["file_to_dataset"].items()
            if owner == dataset
        }
        scopes.append(
            {
                "scope": f"dataset {dataset}",
                "events_n": main_store["dataset_events"][dataset],
                "findings_n": sum(1 for row in finding_rows if row["file"] in files),
                "incidents_n": sum(
                    1 for fileset in member_files.values() if fileset & files
                ),
            }
        )
    chain_files = {chain.get("dataset_file", "") for chain in discover_chains()}
    for chain_file in sorted(chain_files):
        if not chain_file:
            continue
        scopes.append(
            {
                "scope": f"chain file {chain_file}",
                "events_n": _events_for_file(chain_file),
                "findings_n": sum(
                    1 for row in finding_rows if row["file"] == chain_file
                ),
                "incidents_n": sum(
                    1 for fileset in member_files.values() if chain_file in fileset
                ),
            }
        )
    scopes.append(
        {
            "scope": "synthetic benign set",
            "events_n": benign["events_n"],
            "findings_n": benign["findings_n"],
            "incidents_n": benign["incidents_n"],
        }
    )
    return scopes


def _events_for_file(data_file: str) -> int:
    """Count stored events for one data-relative file via its slug table."""
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import events_dir, slug_for_rel

    store = events_dir(REPO_ROOT / "data" / "replay")
    path = store / f"{slug_for_rel(data_file)}.parquet"
    if not path.is_file():
        return 0
    meta = pq.read_metadata(path)
    return int(meta.num_rows)


def _forbidden_markers(ground_truth: dict[str, Any]) -> dict[str, list[str]]:
    """Build the leakage marker sets from ground truth and chain files.

    Returns named lists: ``datasets`` (never legitimate evidence),
    ``files`` (rel paths and basenames, never legitimate evidence),
    ``windows`` (ISO moments, never legitimate evidence as text),
    ``anchors`` (legitimate evidence in the attack store, so only the
    synthetic benign probe is checked against them) and ``ids``
    (ground-truth technique ids; detector output, scrubbed from
    findings and incidents before the check).
    """
    chains = discover_chains()
    datasets: list[str] = []
    for label in ground_truth.values():
        if isinstance(label, dict) and label.get("dataset"):
            datasets.append(str(label["dataset"]))
    files: list[str] = []
    for rel in list(ground_truth):
        if rel:
            files.append(str(rel))
            files.append(str(Path(str(rel)).name))
    for chain in chains:
        if chain.get("dataset_file"):
            files.append(str(chain["dataset_file"]))
            files.append(str(Path(str(chain["dataset_file"])).name))
    anchors: list[str] = []
    windows: list[str] = []
    for chain in chains:
        for step in chain.get("steps", []):
            anchors.extend(str(anchor) for anchor in step.get("anchors", []))
            window = step.get("window", {})
            for moment in (window.get("start", ""), window.get("end", "")):
                if moment:
                    windows.append(str(moment))
    ids = sorted(
        {
            str(technique)
            for label in ground_truth.values()
            if isinstance(label, dict)
            for technique in label.get("techniques", [])
        }
        | {
            str(technique)
            for chain in chains
            for step in chain.get("steps", [])
            for technique in list(step.get("techniques", []))
            + list(step.get("plan_techniques", []))
        }
    )
    return {
        "datasets": sorted({marker for marker in datasets if marker}),
        "files": sorted({marker for marker in files if marker}),
        "windows": sorted({marker for marker in windows if marker}),
        "anchors": sorted({marker for marker in anchors if marker}),
        "ids": ids,
    }


def _finding_related_uids(replay_dir: Path) -> set[str]:
    """Collect the related event uids of every stored finding.

    The file attribution for chain and atomic coverage joins these
    event uids (not the finding uids) back to provenance files.
    """
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import findings_dir

    related: set[str] = set()
    directory = findings_dir(replay_dir)
    if not directory.is_dir():
        return related
    for path in sorted(directory.glob("*.parquet")):
        for record in pq.read_table(path).to_pylist():
            finding = json.loads(str(record["finding_json"]))
            info = finding.get("finding_info") or {}
            for item in info.get("related_events") or []:
                if item.get("uid"):
                    related.add(str(item["uid"]))
    return related


def _flagged_uids(replay_dir: Path) -> set[str]:
    """Return the event uids the loader flagged with in-band technique ids.

    Row-level (not file-level): only these rows are exempt from the
    technique-id check, and they are still checked for dataset, file
    and window markers like every other row.
    """
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import provenance_dir

    flagged: set[str] = set()
    directory = provenance_dir(replay_dir)
    if not directory.is_dir():
        return flagged
    for path in sorted(directory.glob("*.parquet")):
        table = pq.read_table(path, columns=["uid", "in_band_technique_id"])
        for record in table.to_pylist():
            if record["in_band_technique_id"]:
                flagged.add(str(record["uid"]))
    return flagged


def _leakage_over_stores(
    replay_dir: Path,
    benign_replay_dir: Path,
    ground_truth: dict[str, Any],
    incidents: list[Any],
    benign_incidents: list[Any],
) -> list[str]:
    """Run the anti-leakage check over the main and benign stores.

    Dataset/file/window markers must appear in no row anywhere;
    technique ids must appear in no non-in-band event row and in no
    scrubbed finding or incident row (finding attacks and incident
    techniques are detector output, scrubbed first; loader-flagged
    in-band rows are exempt from the technique check at row level and
    counted under the in-band metric instead). Chain anchors are
    checked only on the synthetic benign store, which doubles as the
    injection probe: benign records contain no attack artifacts, so any
    anchor there proves the pipeline injected ground truth. Cheap
    pre-filters (a few short substrings plus two small regexes) select
    the rare candidate rows of the 798k-row event scan; ``check_leakage``
    still names every hit.
    """
    import re

    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import events_dir, findings_dir
    from corvus.normalize.technique_ids import find_technique_ids

    markers = _forbidden_markers(ground_truth)
    datasets = markers["datasets"]
    files = markers["files"]
    windows = markers["windows"]
    anchors = markers["anchors"]
    ids = markers["ids"]
    flagged = _flagged_uids(replay_dir)
    dataset_trigger = re.compile(
        "|".join(re.escape(name) for name in datasets), re.IGNORECASE
    )
    file_trigger = re.compile(r"\.(zip|evtx|etl)\b", re.IGNORECASE)
    window_trigger = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
    hits: list[str] = []

    for path in sorted(events_dir(replay_dir).glob("*.parquet")):
        for record in pq.read_table(path, columns=["uid", "event_json"]).to_pylist():
            dump = str(record["event_json"])
            if dataset_trigger.search(dump):
                hits.extend(check_leakage([dump], datasets, [], check_techniques=False))
            if file_trigger.search(dump):
                hits.extend(check_leakage([dump], files, [], check_techniques=False))
            if window_trigger.search(dump):
                hits.extend(check_leakage([dump], windows, [], check_techniques=False))
            if str(record["uid"]) not in flagged and find_technique_ids(dump):
                hits.extend(check_leakage([dump], [], ids))

    for path in sorted(findings_dir(replay_dir).glob("*.parquet")):
        for record in pq.read_table(path).to_pylist():
            finding = json.loads(str(record["finding_json"]))
            info = finding.get("finding_info") or {}
            related = next(
                (
                    str(item["uid"])
                    for item in info.get("related_events") or []
                    if item.get("uid")
                ),
                "",
            )
            finding["finding_info"]["attacks"] = []
            dump = json.dumps(finding)
            if dataset_trigger.search(dump):
                hits.extend(check_leakage([dump], datasets, [], check_techniques=False))
            if file_trigger.search(dump):
                hits.extend(check_leakage([dump], files, [], check_techniques=False))
            if window_trigger.search(dump):
                hits.extend(check_leakage([dump], windows, [], check_techniques=False))
            if related not in flagged and find_technique_ids(dump):
                hits.extend(check_leakage([dump], [], ids))

    scrubbed_incidents = []
    for incident in incidents:
        scrubbed = dict(incident)
        scrubbed["techniques"] = []
        scrubbed_incidents.append(json.dumps(scrubbed, sort_keys=True, default=str))
    if scrubbed_incidents:
        all_meta = datasets + files + windows + anchors
        hits.extend(check_leakage(scrubbed_incidents, all_meta, ids))

    benign_meta = datasets + files + windows + anchors
    for path in sorted(events_dir(benign_replay_dir).glob("*.parquet")):
        dumps = [
            str(record["event_json"])
            for record in pq.read_table(path, columns=["event_json"]).to_pylist()
        ]
        if dumps:
            hits.extend(check_leakage(dumps, benign_meta, ids))
    for path in sorted(findings_dir(benign_replay_dir).glob("*.parquet")):
        dumps = []
        for record in pq.read_table(path).to_pylist():
            finding = json.loads(str(record["finding_json"]))
            (finding.get("finding_info") or {})["attacks"] = []
            dumps.append(json.dumps(finding))
        if dumps:
            hits.extend(check_leakage(dumps, benign_meta, ids))
    scrubbed_benign = []
    for incident in benign_incidents:
        scrubbed = dict(incident)
        scrubbed["techniques"] = []
        scrubbed_benign.append(json.dumps(scrubbed, sort_keys=True, default=str))
    if scrubbed_benign:
        hits.extend(check_leakage(scrubbed_benign, benign_meta, ids))
    return hits


def _file_in_band(replay_dir: Path) -> dict[str, bool]:
    """Return per-file in-band flags for one replay store."""
    import pyarrow.parquet as pq

    from corvus.adapters.replay.schema import provenance_dir

    flags: dict[str, bool] = {}
    directory = provenance_dir(replay_dir)
    if not directory.is_dir():
        return flags
    import pyarrow.compute as pc

    for path in sorted(directory.glob("*.parquet")):
        table = pq.read_table(path, columns=["file", "in_band_technique_id"])
        files = table.column("file").to_pylist()
        if not files:
            continue
        flagged = pc.sum(table.column("in_band_technique_id")).as_py() or 0
        flags[str(files[0])] = bool(flagged)
    return flags


def _correlation_settings() -> Any:
    """Return correlation settings from the environment, else defaults.

    The harness never needs Postgres or Glimmer: only the session gap,
    max span and auth threshold are read by the correlation call. Real
    environment values win when present; otherwise the documented
    defaults apply and are recorded in the report.
    """
    os.environ.setdefault("DATABASE_URL", "postgresql://127.0.0.1:55432/corvus_harness")
    os.environ.setdefault("GLIMMER_BASE_URL", "http://127.0.0.1:1")

    from corvus.settings import get_settings

    return get_settings()


def compare_inputs(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Name the input groups that differ (a differing group voids deltas)."""
    differing = []
    for group in (
        "rules",
        "datasets",
        "benign",
        "correlation",
        "ground_truth",
    ):
        if baseline.get(group) != current.get(group):
            differing.append(group)
    return differing


def format_deltas(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Render metric deltas between the committed baseline and this run."""
    lines = []
    for key, label in (
        ("benign_incidents", "benign incidents"),
        ("benign_critical", "benign Critical+ incidents"),
        ("atomic_match", "atomic files with a technique match"),
        ("findings", "findings"),
        ("incidents", "incidents"),
        ("in_band_events", "in-band events"),
    ):
        old = baseline.get(key)
        new = current.get(key)
        if isinstance(old, (int, float)) and isinstance(new, (int, float)):
            delta = new - old
            lines.append(f"- {label}: n={old} -> n={new} ({delta:+g})")
    for chain in current.get("chains", []):
        old_chain = next(
            (
                item
                for item in baseline.get("chains", [])
                if item.get("chain_id") == chain.get("chain_id")
            ),
            None,
        )
        if old_chain is None:
            lines.append(
                f"- chain {chain['chain_id']}: new in this run "
                f"(best {chain['best_covered_n']}/{chain['steps_n']}, "
                f"all {chain['all_covered_n']}/{chain['steps_n']})"
            )
            continue
        lines.append(
            f"- chain {chain['chain_id']} best: "
            f"{old_chain['best_covered_n']}/{old_chain['steps_n']} -> "
            f"{chain['best_covered_n']}/{chain['steps_n']} "
            f"({chain['best_covered_n'] - old_chain['best_covered_n']:+d} steps)"
        )
        lines.append(
            f"- chain {chain['chain_id']} all: "
            f"{old_chain['all_covered_n']}/{old_chain['steps_n']} -> "
            f"{chain['all_covered_n']}/{chain['steps_n']} "
            f"({chain['all_covered_n'] - old_chain['all_covered_n']:+d} steps)"
        )
    return lines


def run_harness(
    replay_dir: Path = DEFAULT_REPLAY_DIR,
    rules_dir: Path = DEFAULT_RULES_DIR,
    attack_path: Path = DEFAULT_ATTACK_PATH,
    ground_truth_path: Path = DEFAULT_GROUND_TRUTH,
    benign_hosts: int = BENIGN_HOSTS,
    benign_hours: int = BENIGN_HOURS,
    benign_seed: int = BENIGN_SEED,
) -> tuple[dict[str, Any], int, list[str]]:
    """Run load -> detect -> correlate and return (results, exit_code, notes).

    ``results`` is the JSON-serializable harness output; ``exit_code``
    is 0 when both gates pass, 1 when the benign gate or the leakage
    check fails; ``notes`` are the human-readable gate and delta lines
    the CLI prints.
    """
    from corvus.attack import load_dictionary
    from corvus.correlate.replay import correlate_replay_store, load_replay_findings

    wall_started = time.monotonic()
    notes: list[str] = []
    attack = load_dictionary(attack_path)
    ground_truth: dict[str, Any] = json.loads(
        ground_truth_path.read_text(encoding="utf-8")
    )
    settings = _correlation_settings()

    main_store = inventory_store(replay_dir)
    detect_stats = run_detect(replay_dir, rules_dir, attack)
    correlate_started = time.monotonic()
    incidents = correlate_replay_store(
        replay_dir=replay_dir,
        attack_path=attack_path,
        settings=settings,
        attack=attack,
    )
    correlate_seconds = round(time.monotonic() - correlate_started, 1)
    finding_uids = {
        finding.metadata.uid for finding in load_replay_findings(replay_dir)
    }
    member_sets = [set(incident["event_uids"]) & finding_uids for incident in incidents]
    benign, benign_incidents = run_benign_pipeline(
        benign_hosts, benign_hours, benign_seed, attack, rules_dir
    )

    uid_to_file = _uid_to_file(replay_dir, _finding_related_uids(replay_dir))
    finding_rows = load_finding_rows(replay_dir, attack, uid_to_file)
    chains = [
        chain_step_coverage(chain, finding_rows, member_sets, attack)
        for chain in discover_chains()
    ]
    store_files = set(main_store["file_to_dataset"])
    atomic = atomic_coverage(ground_truth, finding_rows, store_files)
    split = _split_record(ground_truth)

    benign_replay_dir = REPO_ROOT / benign["replay_dir"]
    leakage_hits = _leakage_over_stores(
        replay_dir,
        benign_replay_dir,
        ground_truth,
        incidents,
        benign_incidents,
    )
    benign_tripping = benign["tripping"]
    gates = {
        "benign_critical_gate": "fail" if benign_tripping else "pass",
        "leakage_gate": "fail" if leakage_hits else "pass",
    }
    exit_code = 0 if all(value == "pass" for value in gates.values()) else 1

    inputs = {
        "rules": {
            "files": detect_stats["rules_files"],
            "parsed": detect_stats["rules_parsed"],
            "evaluated": detect_stats["rules_evaluated"],
            "skipped": detect_stats["rules_skipped"],
        },
        "datasets": {
            "replay_files": main_store["event_files"],
            "replay_events": main_store["events_total"],
            "ground_truth_files": len(ground_truth),
            "ground_truth_sha256": sha_of_file(ground_truth_path),
            "chains": [
                {
                    "chain_id": chain.get("chain_id"),
                    "dataset_sha256": chain.get("dataset_sha256"),
                }
                for chain in discover_chains()
            ],
        },
        "benign": {"hosts": benign_hosts, "hours": benign_hours, "seed": benign_seed},
        "correlation": {
            "session_gap_minutes": settings.correlation_session_gap_minutes,
            "max_span_hours": settings.correlation_max_span_hours,
            "auth_failure_threshold": settings.correlation_auth_failure_threshold,
        },
        "ground_truth": {
            "label_sources": sorted(
                str(label.get("label_source"))
                for label in ground_truth.values()
                if isinstance(label, dict)
            )
        },
    }
    window_start = main_store["window_start"]
    window_end = main_store["window_end"]
    results = {
        "meta": {
            "producing_command": (
                f"corvus eval run --replay-dir {replay_dir} "
                f"--rules-dir {rules_dir} --attack {attack_path} "
                f"--ground-truth {ground_truth_path} "
                f"--benign-hosts {benign_hosts} "
                f"--benign-hours {benign_hours} --benign-seed {benign_seed}"
            ),
            "git_commit": git_commit(),
            "generated_at": maintainer_today(),
            "data_window": {
                "start": format_ms(window_start) if window_start else None,
                "end": format_ms(window_end) if window_end else None,
            },
            "runtime_seconds": round(time.monotonic() - wall_started, 1),
            "detect_seconds": detect_stats["seconds"],
            "correlate_seconds": correlate_seconds,
        },
        "inputs": inputs,
        "n": {
            "events": main_store["events_total"],
            "findings": detect_stats["findings"],
            "incidents": len(incidents),
        },
        "benign": benign,
        "benign_incidents": benign["incidents_n"],
        "benign_critical": len(benign_tripping),
        "chains": chains,
        "atomic": {
            "files_with_ground_truth_n": atomic["files_with_ground_truth_n"],
            "in_store_n": atomic["in_store_n"],
            "not_in_store_n": atomic["not_in_store_n"],
            "with_finding_n": atomic["with_finding_n"],
            "with_match_n": atomic["with_match_n"],
        },
        "atomic_match": atomic["with_match_n"],
        "atomic_detail": atomic["per_file"],
        "atomic_not_in_store": atomic["not_in_store"],
        "findings": detect_stats["findings"],
        "incidents": len(incidents),
        "incidents_by_floor": {
            str(floor): sum(
                1 for incident in incidents if incident["severity_floor"] == floor
            )
            for floor in sorted({incident["severity_floor"] for incident in incidents})
        },
        "compression": _compression(
            main_store, detect_stats, incidents, finding_rows, benign
        ),
        "in_band_events": main_store["in_band_events"],
        "in_band": {
            "events_with_flag_n": main_store["in_band_events"],
            "files_with_flag_n": sum(
                1 for flagged in main_store["file_in_band"].values() if flagged
            ),
        },
        "leakage": {
            "status": gates["leakage_gate"],
            "hits_n": len(leakage_hits),
            "hits": leakage_hits[:20],
        },
        "gates": gates,
        "split": split,
    }
    if benign_tripping:
        notes.append(
            f"FAIL benign gate: n={len(benign_tripping)} synthetic incident(s) "
            f"at Critical+ (gate: zero >= Critical)"
        )
    else:
        notes.append(
            f"PASS benign gate: n={benign['incidents_n']} synthetic incident(s), "
            f"zero at Critical+ (by severity {benign['by_severity']})"
        )
    if leakage_hits:
        notes.append(f"FAIL leakage gate: n={len(leakage_hits)} hit(s)")
    else:
        notes.append("PASS leakage gate: no dataset, file, technique or anchor strings")
    return results, exit_code, notes


def render_markdown(results: dict[str, Any], delta_lines: list[str]) -> str:
    """Render ``eval/reports/latest.md`` (counts and ids only, every n named)."""
    meta = results["meta"]
    benign = results["benign"]
    lines = [
        "# Corvus eval — latest",
        "",
        f"Producing command: `{meta['producing_command']}` (n = 1 run, "
        f"git commit `{meta['git_commit']}`, generated {meta['generated_at']}).",
        f"Data window: {meta['data_window']['start']} to {meta['data_window']['end']} "
        f"(`time` min/max over n={results['n']['events']} stored events). "
        f"Runtime: {meta['runtime_seconds']} s wall "
        f"(detect {meta['detect_seconds']} s, "
        f"correlate {meta['correlate_seconds']} s).",
        f"Gates: benign Critical gate {results['gates']['benign_critical_gate']}, "
        f"leakage gate {results['gates']['leakage_gate']}.",
        "",
        "## Inputs",
        "",
        f"- Sigma rules: n={results['inputs']['rules']['files']} files, "
        f"n={results['inputs']['rules']['parsed']} parsed, "
        f"n={results['inputs']['rules']['evaluated']} evaluated "
        f"(skipped {results['inputs']['rules']['skipped']}).",
        f"- Replay store: n={results['inputs']['datasets']['replay_files']} files, "
        f"n={results['inputs']['datasets']['replay_events']} events; "
        f"ground truth n={results['inputs']['datasets']['ground_truth_files']} files "
        f"(sha256 `{results['inputs']['datasets']['ground_truth_sha256'][:16]}…`).",
        f"- Benign (DECLARED SYNTHETIC): hosts={benign['hosts']}, "
        f"hours={benign['hours']}, seed={benign['seed']}, "
        f"n={benign['records_n']} records.",
        f"- Correlation: session gap "
        f"{results['inputs']['correlation']['session_gap_minutes']} min, max span "
        f"{results['inputs']['correlation']['max_span_hours']} h, auth threshold "
        f"{results['inputs']['correlation']['auth_failure_threshold']}.",
        "",
        "## Benign false positives (DECLARED SYNTHETIC, gate: zero >= Critical)",
        "",
        f"- Records: n={benign['records_n']}; events: n={benign['events_n']} "
        f"(unmapped n={benign['unmapped_n']}); findings: n={benign['findings_n']}; "
        f"incidents: n={benign['incidents_n']}.",
        "",
        "| severity | incidents (n) |",
        "| --- | --- |",
    ]
    for level in (1, 2, 3, 4, 5, 6):
        count = benign["by_severity"].get(str(level), 0)
        lines.append(f"| {level} {ID_TO_NAME[level]} | {count} |")
    lines += [
        "",
        f"- Incidents at Critical or above: n={results['benign_critical']} (gate).",
        "",
        "## Chain detection (per step, never a lone boolean)",
        "",
    ]
    for chain in results["chains"]:
        lines += [
            f"### {chain['chain_id']} (n={chain['steps_n']} steps, "
            f"file `{chain['dataset_file']}`)",
            "",
            f"- Best incident covers n={chain['best_covered_n']} steps; "
            f"all incidents together cover n={chain['all_covered_n']} steps.",
            "",
            "| step | window (UTC) | techniques | best | all |",
            "| --- | --- | --- | --- | --- |",
        ]
        for step in chain["steps"]:
            lines.append(
                f"| {step['step']} {step['name']} | {step['window']['start']} .. "
                f"{step['window']['end']} | {', '.join(step['techniques'])} | "
                f"{'yes' if step['covered_by_best'] else 'no'} | "
                f"{'yes' if step['covered_by_all'] else 'no'} |"
            )
        lines.append("")
    lines += [
        "## Atomic technique coverage (OTRF otrf-metadata files only)",
        "",
        f"- Files with ground-truth techniques: "
        f"n={results['atomic']['files_with_ground_truth_n']}; ",
        f"n={results['atomic']['in_store_n']} with events in the store, "
        f"n={results['atomic']['not_in_store_n']} without (network/pcap, never "
        "ingested: excluded, not counted as misses).",
        f"- n={results['atomic']['with_finding_n']} with >= 1 finding; "
        f"n={results['atomic']['with_match_n']} with a finding whose technique "
        "parent matches the ground truth.",
        "",
        "| file | findings (n) | technique match | matched techniques |",
        "| --- | --- | --- | --- |",
    ]
    for row in results["atomic_detail"]:
        slug = str(row["file"]).replace(".zip", "").replace(".evtx", "")
        lines.append(
            f"| {slug} | {row['findings_n']} | "
            f"{'yes' if row['matched'] else 'no'} | "
            f"{', '.join(row['matched_techniques'])} |"
        )
    lines += [
        "",
        "## Compression (events -> findings -> incidents per dataset)",
        "",
        "| scope | events (n) | findings (n) | incidents (n) |",
        "| --- | --- | --- | --- |",
    ]
    for scope in results["compression"]:
        lines.append(
            f"| {scope['scope']} | {scope['events_n']} | "
            f"{scope['findings_n']} | {scope['incidents_n']} |"
        )
    lines += [
        "",
        "## In-band technique ids (provenance flag, D18)",
        "",
        f"- Events carrying an in-band technique reference: "
        f"n={results['in_band']['events_with_flag_n']} in "
        f"n={results['in_band']['files_with_flag_n']} files.",
        "",
        "## Anti-leakage",
        "",
        f"- Status: {results['leakage']['status']} "
        "(checked rows carry no dataset, file, technique or anchor strings; "
        "finding attacks and incident techniques scrubbed as detector output; "
        f"in-band rows exempt from the technique check; "
        f"n={results['leakage']['hits_n']} hits).",
    ]
    for hit in results["leakage"]["hits"]:
        lines.append(f"- {hit}")
    lines += [
        "",
        "## Train/test split (OTRF recordings per technique)",
        "",
        f"- Techniques: n={results['split']['techniques_n']} "
        f"({results['split']['testable_n']} testable, "
        f"{results['split']['untestable_n']} untestable); "
        f"multi-label files: n={results['split']['multi_label_files_n']}; "
        f"excluded non-ATT&CK ids: {results['split']['excluded']}.",
        "",
        "| technique | train (n) | test (n) | untestable |",
        "| --- | --- | --- | --- |",
    ]
    for technique, entry in results["split"]["per_technique"].items():
        lines.append(
            f"| {technique} | {entry['train_n']} | {entry['test_n']} | "
            f"{entry['untestable']} |"
        )
    lines += ["", "## Deltas vs the committed baseline", ""]
    lines.extend(delta_lines or ["- no committed baseline to compare against."])
    lines += [
        "",
        "## Incidents per severity floor",
        "",
        "| floor | incidents (n) |",
        "| --- | --- |",
    ]
    for floor, count in results["incidents_by_floor"].items():
        lines.append(f"| {floor} | {count} |")
    lines.append("")
    return "\n".join(lines)


def read_baseline(path: Path) -> tuple[dict[str, Any] | None, str]:
    """Read the delta baseline and name its provenance.

    The baseline is the *committed* file (``git show HEAD:<path>`` for
    paths inside the repository), never the working tree, which already
    holds this run's output by the time deltas print. An explicit path
    outside the repository is read as a file. Returns the baseline (or
    ``None``) plus ``committed``, ``file`` or ``none``.
    """
    try:
        rel = path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        rel = None
    if rel is not None:
        try:
            shown = subprocess.run(
                ["git", "show", f"HEAD:{rel.as_posix()}"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except OSError, subprocess.SubprocessError:
            shown = None
        if shown is not None and shown.returncode == 0:
            try:
                return json.loads(shown.stdout), "committed"
            except ValueError:
                return None, "none"
        return None, "none"
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8")), "file"
        except ValueError:
            return None, "none"
    return None, "none"


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``corvus eval run``; writes latest.md and latest.json."""
    parser = argparse.ArgumentParser(prog="corvus eval run", description=__doc__)
    parser.add_argument("--replay-dir", default=str(DEFAULT_REPLAY_DIR))
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--attack", default=str(DEFAULT_ATTACK_PATH))
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH))
    parser.add_argument("--benign-hosts", type=int, default=BENIGN_HOSTS)
    parser.add_argument("--benign-hours", type=int, default=BENIGN_HOURS)
    parser.add_argument("--benign-seed", type=int, default=BENIGN_SEED)
    parser.add_argument("--report-md", default=str(DEFAULT_REPORT_MD))
    parser.add_argument("--report-json", default=str(DEFAULT_REPORT_JSON))
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_REPORT_JSON),
        help="Delta baseline (the git HEAD version is used for in-repo paths).",
    )
    args = parser.parse_args(argv)

    for name in ("replay-dir", "rules-dir", "attack", "ground-truth"):
        path = Path(getattr(args, name.replace("-", "_")))
        if not path.exists():
            print(f"error: --{name} missing: {path}", file=sys.stderr)
            return 2

    baseline, provenance = read_baseline(Path(args.baseline))

    results, exit_code, notes = run_harness(
        replay_dir=Path(args.replay_dir),
        rules_dir=Path(args.rules_dir),
        attack_path=Path(args.attack),
        ground_truth_path=Path(args.ground_truth),
        benign_hosts=args.benign_hosts,
        benign_hours=args.benign_hours,
        benign_seed=args.benign_seed,
    )

    delta_lines: list[str] = []
    if baseline is None:
        delta_lines = [
            "- no committed baseline to compare against "
            "(latest.json is not committed yet; commit this run first)."
        ]
    elif provenance == "file":
        delta_lines = [
            "- baseline is an explicit file, not the committed latest.json; "
            "deltas below are informational only."
        ]
        delta_lines.extend(
            format_deltas(
                {
                    "benign_incidents": baseline.get("benign_incidents"),
                    "benign_critical": baseline.get("benign_critical"),
                    "atomic_match": baseline.get("atomic_match"),
                    "findings": baseline.get("findings"),
                    "incidents": baseline.get("incidents"),
                    "in_band_events": baseline.get("in_band_events"),
                    "chains": baseline.get("chains", []),
                },
                {
                    "benign_incidents": results["benign_incidents"],
                    "benign_critical": results["benign_critical"],
                    "atomic_match": results["atomic_match"],
                    "findings": results["findings"],
                    "incidents": results["incidents"],
                    "in_band_events": results["in_band_events"],
                    "chains": results["chains"],
                },
            )
        )
    else:
        differing = compare_inputs(baseline.get("inputs", {}), results["inputs"])
        if differing:
            delta_lines = [
                "- inputs differ "
                f"({', '.join(differing)}); no misleading delta reported. "
                "Re-baseline by committing this run's latest.json."
            ]
        else:
            delta_lines = format_deltas(
                {
                    "benign_incidents": baseline.get("benign_incidents"),
                    "benign_critical": baseline.get("benign_critical"),
                    "atomic_match": baseline.get("atomic_match"),
                    "findings": baseline.get("findings"),
                    "incidents": baseline.get("incidents"),
                    "in_band_events": baseline.get("in_band_events"),
                    "chains": baseline.get("chains", []),
                },
                {
                    "benign_incidents": results["benign_incidents"],
                    "benign_critical": results["benign_critical"],
                    "atomic_match": results["atomic_match"],
                    "findings": results["findings"],
                    "incidents": results["incidents"],
                    "in_band_events": results["in_band_events"],
                    "chains": results["chains"],
                },
            )

    report_md = Path(args.report_md)
    report_json = Path(args.report_json)
    report_md.parent.mkdir(parents=True, exist_ok=True)
    report_md.write_text(render_markdown(results, delta_lines), encoding="utf-8")
    report_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {report_md} and {report_json}")
    for note in notes:
        print(note)
    print("deltas vs the committed baseline:")
    for line in delta_lines:
        print(line)
    print(f"runtime: {results['meta']['runtime_seconds']} s wall")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
