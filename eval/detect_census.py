"""Producing script for ``eval/reports/day2_replay_detect.md``.

Runs the full replay detection (load Sigma rules, evaluate over the
replay store, write findings) and joins the findings with the ground
truth: rule/skip counts, findings per level and per tactic (whole
store and the APT29 day-1 file), OTRF atomic-file coverage, APT29
step windows, and the dataset-reference disclosure with the OTRF and
APT29 numbers recomputed without the disclosed rules.

Every published number carries its n; the report holds counts and
rule ids only, never event content. Usage::

    ulimit -n 4096
    .venv/bin/python eval/detect_census.py
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "data" / "sigma" / "rules"
REPLAY_DIR = REPO / "data" / "replay"
ATTACK_PATH = REPO / "data" / "attack" / "enterprise.json"
GROUND_TRUTH_PATH = REPO / "data" / "ground_truth.json"
APT29_PATH = REPO / "eval" / "apt29_day1_ground_truth.json"
REPORT_PATH = REPO / "eval" / "reports" / "day2_replay_detect.md"

#: Human-written causes for rules whose match count changes by more
#: than 5 between the old and the new null semantics, keyed by rule
#: id. Each cause was verified against the rule's detection and the
#: replay rows (see the report); the script renders them under the
#: delta table.
EXPLANATIONS: dict[str, str] = {
    "5ef9853e-4d0e-4a70-846f-a9ca37d876da": (
        "LSASS credential-dumping rule (process_access): selection matches "
        "lsass.exe accesses with dumping masks and call-trace DLLs. All 33 "
        "gained rows carry no SourceUser key in the wire payload (Sysmon 10 "
        "logs none; flat, winlog and EVTX layouts, read with the "
        "normalizer's own extraction), so `not filter_main_system_user` is "
        "null over them under the old semantics (excluded) and true under "
        "Sigma NOT (included)."
    ),
    "49f2f17b-b4c8-4172-a68b-d5bf95d05130": (
        "UAC bypass via ICMLuaUtil (process_creation): selection is a "
        "dllhost parent with the COM Processid. The 2 pre-existing matches "
        "carry a non-WerFault OriginalFileName (Cmd.Exe, WinWord.exe). The "
        "3 gained rows have Image cmd.exe but no OriginalFileName key in "
        "the wire payload, so the negated WerFault disjunction is null "
        "over them under the old semantics (excluded) and true under "
        "Sigma NOT (included)."
    ),
    "d797268e-28a9-49a7-b9a8-2f5039011c5c": (
        "WSReset UAC-bypass rule (process_creation): the gained row "
        "(EVTX layout, wire payload read) has ParentImage WSReset.exe and "
        "Image cmd.exe but no OriginalFileName key, so `not (Image "
        "conhost or OriginalFileName CONHOST)` is null over it under the "
        "old semantics (excluded) and true under Sigma NOT (included)."
    ),
    "b655a06a-31c0-477a-95c2-3726b83d649d": (
        "Suspicious userinit child (process_creation): the gained row "
        "(EVTX layout, wire payload read) parents userinit.exe to a "
        "randomly-named executable whose CommandLine matches none of the "
        "negated netlogon/explorer alternatives, with no OriginalFileName "
        "key, so the negated disjunction is null over it under the old "
        "semantics (excluded) and true under Sigma NOT (included)."
    ),
}

#: Reference markers that inflate detection (a rule written from the
#: measured dataset detects it by construction).
DISCLOSURE_MARKERS = (
    "otrf",
    "security-datasets",
    "mordor",
    "apt29",
    "attack-evaluation",
    "evtx-attack-samples",
)

APT29_FILE = (
    "security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"
)


def parse_ms(moment: str) -> int:
    """Parse an ISO-8601 UTC moment to epoch milliseconds."""
    parsed = datetime.fromisoformat(moment.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def main() -> None:
    from corvus.adapters.replay.findings import write_findings
    from corvus.adapters.replay.schema import findings_dir, provenance_dir
    from corvus.attack import load_dictionary, normalize_id
    from corvus.detect import load_rules
    from corvus.detect.engine import evaluate

    wall_started = time.monotonic()
    attack = load_dictionary(ATTACK_PATH)
    attack_version = str(
        json.loads(ATTACK_PATH.read_text(encoding="utf-8")).get(
            "attack_version", "v20.0"
        )
    ).removeprefix("v")

    compiled, load_stats = load_rules(RULES_DIR)
    by_rule = {rule.rule_id: rule for rule in compiled}
    matches, infos, eval_stats = evaluate(REPLAY_DIR, compiled)
    write_summary = write_findings(
        REPLAY_DIR, compiled, matches, infos, attack, attack_version
    )

    # Old-vs-new semantics delta (measurement only): the legacy
    # strict backend plus no raw fallback reproduces the previous
    # report's counts, so the report can show the per-rule delta.
    legacy_compiled, _ = load_rules(RULES_DIR, strict_nulls=True)
    legacy_matches, _, legacy_stats = evaluate(
        REPLAY_DIR, legacy_compiled, raw_fallback=False
    )
    before = {
        rule.rule_id: len(legacy_matches.get(rule.rule_id, ())) for rule in compiled
    }
    after = {rule.rule_id: len(matches.get(rule.rule_id, ())) for rule in compiled}

    finding_rows: list[dict[str, Any]] = []
    for path in sorted(findings_dir(REPLAY_DIR).glob("*.parquet")):
        finding_rows.extend(pq.read_table(path).to_pylist())

    uid_to_file: dict[str, str] = {}
    for path in sorted(provenance_dir(REPLAY_DIR).glob("*.parquet")):
        for record in pq.read_table(path, columns=["uid", "file"]).to_pylist():
            uid_to_file[str(record["uid"])] = str(record["file"])

    ground_truth: dict[str, Any] = json.loads(
        GROUND_TRUTH_PATH.read_text(encoding="utf-8")
    )
    apt29: dict[str, Any] = json.loads(APT29_PATH.read_text(encoding="utf-8"))

    def parent_of(technique_id: str) -> str:
        canonical = normalize_id(technique_id) or technique_id
        entry = attack.resolve(canonical)
        if entry is not None and entry.is_subtechnique and entry.parent:
            return entry.parent
        return canonical

    def attack_sets(finding_json: str) -> tuple[set[str], set[str], set[str]]:
        """Return (techniques, parent-expanded techniques, tactics)."""
        finding = json.loads(finding_json)
        info = finding.get("finding_info") or {}
        techniques: set[str] = set()
        tactics: set[str] = set()
        for item in info.get("attacks") or []:
            tactic = item.get("tactic") or {}
            if tactic.get("name"):
                tactics.add(str(tactic["name"]))
            technique = item.get("technique") or {}
            sub = item.get("sub_technique") or {}
            if sub.get("uid"):
                techniques.add(str(sub["uid"]))
            elif technique.get("uid"):
                techniques.add(str(technique["uid"]))
        expanded = set()
        for technique in techniques:
            canonical = normalize_id(technique) or technique
            expanded.add(canonical)
            expanded.add(parent_of(canonical))
        return techniques, expanded, tactics

    def gt_expanded(techniques: list[Any]) -> set[str]:
        out: set[str] = set()
        for raw in techniques:
            canonical = normalize_id(raw) or str(raw)
            out.add(canonical)
            out.add(parent_of(canonical))
        return out

    def related_uid(row: dict[str, Any]) -> str:
        finding = json.loads(row["finding_json"])
        return str(finding["finding_info"]["related_events"][0]["uid"])

    disclosed: dict[str, list[str]] = {}
    for rule in compiled:
        hits = sorted(
            {
                marker
                for marker in DISCLOSURE_MARKERS
                for reference in rule.references
                if marker in reference.lower()
            }
        )
        if hits:
            disclosed[rule.rule_id] = hits

    lines: list[str] = []
    add = lines.append
    add("# Day-2 replay detect")
    add("")
    add("SigmaHQ rules over the OCSF replay store: counts and ids only,")
    add("no event content. Produced by `eval/detect_census.py`; inputs are")
    add("the pinned SigmaHQ release (`data/sigma/rules`), the replay store")
    add("(`data/replay`), `data/ground_truth.json`,")
    add("`eval/apt29_day1_ground_truth.json`, and")
    add("`data/attack/enterprise.json`. Date: 2026-10-28.")
    add("")
    add("## Method")
    add("")
    add("- Each Sigma logsource routes to one OCSF slice; each slice is")
    add("  scanned once per rule group. Slices, field maps and the null")
    add("  semantics (Sigma `NOT`; placeholders re-read from the")
    add("  pre-mapper payload in every raw layout) are documented in")
    add("  `docs/ocsf.md`.")
    add(
        "- Technique ids resolve through the pinned ATT&CK dictionary v20.0"
        " (`data/attack/enterprise.json`); tactic names below are its"
        " names (for example Defense Impairment, Stealth)."
    )
    add("- A finding carries technique ids; matching below compares at")
    add("  the parent-or-self level on both sides: a finding technique,")
    add("  its parent when it is a sub-technique, and the same expansion")
    add("  of each ground-truth id. A tactic count names a finding once")
    add("  per tactic its attacks list.")
    add("")
    add("## Null semantics delta (old vs new)")
    add("")
    add(
        "Old: strict nulls (a null field satisfies no condition,"
        " negated or not) with no raw fallback. New: stock Sigma"
        " semantics (an absent field satisfies `NOT`) plus the raw"
        " fallback (a nulled placeholder compares as the logged"
        " value). Before/after are matched-event counts per rule."
    )
    add("")
    changed = sorted(
        (
            (rule_id, before[rule_id], after[rule_id])
            for rule_id in before
            if before[rule_id] != after[rule_id]
        ),
        key=lambda row: (abs(row[2] - row[1]), row[0]),
        reverse=True,
    )
    up = sum(1 for _, old, new in changed if new > old)
    down = sum(1 for _, old, new in changed if new < old)
    add(
        f"- changed rules: n={len(changed)} of n={len(before)} evaluated;"
        f" {up} gain matches, {down} lose matches,"
        f" {len(before) - len(changed)} unchanged"
    )
    add("")
    add("| rule id | before | after | delta |")
    add("| --- | --- | --- | --- |")
    for rule_id, old, new in changed:
        add(f"| {rule_id} | {old} | {new} | {new - old:+d} |")
    add("")
    explained = [
        (rule_id, EXPLANATIONS[rule_id])
        for rule_id, _, _ in changed
        if rule_id in EXPLANATIONS
    ]
    if explained:
        add("Rules whose count changes by more than 5, explained:")
        add("")
        for rule_id, text in explained:
            add(f"- `{rule_id}`: {text}")
        add("")
    add("## Rules")
    add("")
    add(
        f"- rule files: n={load_stats.files}; parsed rules: n={load_stats.parsed_rules}"
    )
    add(
        f"- evaluated: n={load_stats.evaluated}; "
        f"skipped: n={sum(load_stats.skipped.values())}"
    )
    add("")
    add("| reason | n | top details |")
    add("| --- | --- | --- |")
    for reason in (
        "status",
        "logsource",
        "event_id",
        "unmapped_field",
        "unsupported_construct",
    ):
        bucket = load_stats.skip_details.get(reason, {})
        total = load_stats.skipped.get(reason, 0)
        top = ", ".join(
            f"{detail} ({count})"
            for detail, count in sorted(bucket.items(), key=lambda item: -item[1])[:5]
        )
        add(f"| {reason} | {total} | {top} |")
    add("")
    add(
        "Runtime conversion errors during evaluation: "
        f"n={len(eval_stats.rules_errored)}."
    )
    add("")

    write_findings_section(
        add,
        attack_version,
        by_rule,
        finding_rows,
        uid_to_file,
        ground_truth,
        apt29,
        disclosed,
        attack_sets,
        gt_expanded,
        related_uid,
        eval_stats,
        write_summary,
        wall_started,
    )
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {REPORT_PATH} ({len(finding_rows)} findings)")


def write_findings_section(
    add: Callable[[str], None],
    attack_version: str,
    by_rule: dict[str, Any],
    finding_rows: list[dict[str, Any]],
    uid_to_file: dict[str, str],
    ground_truth: dict[str, Any],
    apt29: dict[str, Any],
    disclosed: dict[str, list[str]],
    attack_sets: Callable[[str], tuple[set[str], set[str], set[str]]],
    gt_expanded: Callable[[list[Any]], set[str]],
    related_uid: Callable[[dict[str, Any]], str],
    eval_stats: Any,
    write_summary: Any,
    wall_started: float,
) -> None:
    """Append the metric sections (split out for readability)."""
    del attack_version, write_summary

    level_counts: dict[str, int] = {}
    tactic_counts: dict[str, int] = {}
    apt29_level: dict[str, int] = {}
    apt29_tactic: dict[str, int] = {}
    untagged = 0
    for row in finding_rows:
        _tech, _expanded, tactics = attack_sets(row["finding_json"])
        level_counts[row["level"]] = level_counts.get(row["level"], 0) + 1
        if not tactics:
            untagged += 1
        for tactic in tactics or {"(no tactic)"}:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        if uid_to_file.get(related_uid(row)) == APT29_FILE:
            apt29_level[row["level"]] = apt29_level.get(row["level"], 0) + 1
            for tactic in tactics or {"(no tactic)"}:
                apt29_tactic[tactic] = apt29_tactic.get(tactic, 0) + 1
    n_findings = len(finding_rows)

    add("## Findings")
    add("")
    add(f"- findings total: n={n_findings} on n={eval_stats.events_matched} events")
    add(f"- findings on the APT29 day-1 file: n={sum(apt29_level.values())}")
    add(f"- findings with no ATT&CK tactic: n={untagged}")
    add("")
    add("| level | whole store (n) | APT29 day-1 (n) |")
    add("| --- | --- | --- |")
    for level in ("critical", "high", "medium", "low", "informational"):
        add(f"| {level} | {level_counts.get(level, 0)} | {apt29_level.get(level, 0)} |")
    add("")
    add("| tactic | whole store (n) | APT29 day-1 (n) |")
    add("| --- | --- | --- |")
    for tactic in sorted(set(tactic_counts) | set(apt29_tactic)):
        add(
            f"| {tactic} | {tactic_counts.get(tactic, 0)} | "
            f"{apt29_tactic.get(tactic, 0)} |"
        )
    add("")

    otrf_files = sorted(
        key
        for key, value in ground_truth.items()
        if value.get("label_source") == "otrf-metadata" and value.get("techniques")
    )
    # Only files with events in the replay store can produce findings;
    # the network (pcap) datasets were never ingested, so they are
    # reported separately instead of counted as misses.
    store_files = set(uid_to_file.values())
    otrf_in_store = [key for key in otrf_files if key in store_files]
    otrf_not_in_store = [key for key in otrf_files if key not in store_files]
    findings_by_file: dict[str, list[dict[str, Any]]] = {}
    for row in finding_rows:
        findings_by_file.setdefault(uid_to_file.get(related_uid(row), ""), []).append(
            row
        )

    add("## OTRF atomic files with techniques")
    add("")
    add(
        f"- ground-truth files with techniques: n={len(otrf_files)}; "
        f"n={len(otrf_in_store)} have events in the replay store, "
        f"n={len(otrf_not_in_store)} do not (network/pcap datasets, "
        "never ingested: no findings possible, excluded below)"
    )
    add("")
    for label, drop in (
        ("all rules", set()),
        ("without disclosed rules", set(disclosed)),
    ):
        with_finding = 0
        with_match = 0
        table = []
        for data_file in otrf_in_store:
            file_rows = [
                row
                for row in findings_by_file.get(data_file, [])
                if row["rule_id"] not in drop
            ]
            ground = gt_expanded(ground_truth[data_file].get("techniques", []))
            matched = sorted(
                {
                    technique
                    for row in file_rows
                    for technique in attack_sets(row["finding_json"])[1]
                    if technique in ground
                }
            )
            if file_rows:
                with_finding += 1
            if matched:
                with_match += 1
            table.append((data_file, len(file_rows), bool(matched), matched))
        add(
            f"- {label}: n={len(otrf_in_store)} files with techniques in the store; "
            f"{with_finding} have >=1 finding; {with_match} have a "
            "finding whose technique (parent) matches ground truth"
        )
        add("")
        add("| file | findings (n) | technique match | matched techniques |")
        add("| --- | --- | --- | --- |")
        for data_file, count, is_match, techniques in table:
            slug = data_file.replace(".zip", "").replace(".evtx", "")
            add(
                f"| {slug} | {count} | {'yes' if is_match else 'no'} | "
                f"{', '.join(techniques)} |"
            )
        add("")

    def in_window(row: dict[str, Any], start: int, end: int) -> bool:
        return (
            uid_to_file.get(related_uid(row), "") == APT29_FILE
            and start <= int(row["time"]) <= end
        )

    add("## APT29 day-1 steps")
    add("")
    add("Step windows overlap, so per-step finding counts do not sum to")
    add("the file total.")
    add("")
    for label, drop in (
        ("all rules", set()),
        ("without disclosed rules", set(disclosed)),
    ):
        add(f"### {label}")
        add("")
        add(
            "| step | window (UTC) | findings in window (n) | "
            "technique match | matched techniques |"
        )
        add("| --- | --- | --- | --- | --- |")
        for step in apt29["steps"]:
            window = step.get("window", {})
            start, end = parse_ms(window["start"]), parse_ms(window["end"])
            ground = gt_expanded(step.get("techniques", []))
            window_rows = [
                row
                for row in finding_rows
                if row["rule_id"] not in drop and in_window(row, start, end)
            ]
            matched = sorted(
                {
                    technique
                    for row in window_rows
                    for technique in attack_sets(row["finding_json"])[1]
                    if technique in ground
                }
            )
            add(
                f"| {step['step']} {step['name']} | {window['start']} .. "
                f"{window['end']} | {len(window_rows)} | "
                f"{'yes' if matched else 'no'} | {', '.join(matched)} |"
            )
        add("")

    add("## Disclosure: rules referencing the measured datasets")
    add("")
    add("In-scope rules whose `references` cite OTRF / Security-Datasets,")
    add("Mordor, the APT29 evaluations, or EVTX-ATTACK-SAMPLES. A rule")
    add("written from the dataset being measured detects it by")
    add("construction, so the OTRF and APT29 numbers above are repeated")
    add("without these rules.")
    add("")
    add(f"- disclosed rules: n={len(disclosed)} of n={len(by_rule)} evaluated")
    add("")
    add("| rule id | markers |")
    add("| --- | --- |")
    for rule_id in sorted(disclosed):
        add(f"| {rule_id} | {', '.join(disclosed[rule_id])} |")
    add("")

    total_seconds = time.monotonic() - wall_started
    add("## Runtime")
    add("")
    add(
        f"- full replay store: {eval_stats.seconds:.1f}s evaluate "
        f"({eval_stats.events_scanned} rows scanned across group passes), "
        f"{total_seconds:.1f}s end to end including rule load, the legacy "
        "measurement pass for the delta above, finding writes, and the "
        "report join"
    )
    add(f"- peak RSS: {eval_stats.peak_rss_mb:.0f} MiB (process max resident set)")
    add("")


if __name__ == "__main__":
    main()
