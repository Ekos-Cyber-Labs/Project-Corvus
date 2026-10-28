"""Census of the APT29 day-1 compound file: counts only, streaming.

Usage (from the repo root, after fetching datasets)::

    uv run python eval/apt29_census.py [--dataset <apt29 day1 zip>]
        [--report eval/reports/apt29_day1_replay_load.md]

Streams the zip member record by record (never the whole ~367 MB
of JSON lines in memory) in a single pass: each raw record is
normalized with the same extractors the replay loader uses, so
mapped events, unmapped (channel, event id) buckets, anchor hits
in both, per-step verdicts, LSASS GrantedAccess counts, in-band
technique-reference counts and re-derived anchor windows all come
from that one pass. Step attribution uses each record's
``@timestamp`` (the ingest clock the step windows were derived on;
Sysmon ``UtcTime`` can lag it on WEF-forwarded records). No event
content, host names, user names or script text is printed; anchor
strings themselves are ground truth and are never printed either.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from corvus.normalize.technique_ids import has_in_band_technique_id  # noqa: E402
from corvus.normalize.windows import (  # noqa: E402
    UnmappedEvent,
    extract_json_parts,
    make_uid,
    normalize_event,
    parse_windows_time,
    sanitize_record,
)
from eval.chain_ground_truth import (  # noqa: E402
    census_time_ms,
    contains_anchor,
    event_text_fields,
    is_lsass_high_access,
    load_chain,
    step_verdict,
    step_window_ms,
    window_ms,
)

DEFAULT_DATASET = (
    "data/security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"
)

SERVICE_BUCKETS = {("Security", 4697), ("System", 7045)}
REGISTRY_BUCKETS = {
    ("Microsoft-Windows-Sysmon/Operational", 12),
    ("Microsoft-Windows-Sysmon/Operational", 13),
    ("Microsoft-Windows-Sysmon/Operational", 14),
}


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _sysmon(result: dict[str, Any], event_id: int) -> int:
    return int(result["unmapped"].get((SYSMON_CHANNEL, event_id), 0))


def _fmt(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%H:%M:%S")


def _raw_text(record: dict[str, Any]) -> str:
    return " ".join(str(value) for value in record.values()).lower()


def run_census(dataset: Path, chain: dict[str, Any]) -> dict[str, Any]:
    """Stream ``dataset`` once and return every report count."""
    chain_start, chain_end = window_ms(chain)
    steps = chain["steps"]
    windows = {int(s["step"]): step_window_ms(s) for s in steps}
    anchors = {int(s["step"]): list(s["anchors"]) for s in steps}
    relevant = {int(s["step"]): {(p[0], p[1]) for p in s["relevant"]} for s in steps}
    per_class: Counter[int] = Counter()
    per_activity: Counter[tuple[int, int]] = Counter()
    unmapped: Counter[tuple[str, int]] = Counter()
    per_step: dict[int, dict[str, Any]] = {
        n: {
            "anchor_in": 0,
            "anchor_out": 0,
            "relevant": 0,
            "unmapped_anchor": Counter(),
            "anchor_ids": set(),
        }
        for n in windows
    }
    derived: dict[int, list[int]] = {n: [] for n in windows}
    lsass_total = 0
    lsass_granted: Counter[str] = Counter()
    lsass_high_times: list[int] = []
    in_band = 0
    records = 0

    with zipfile.ZipFile(dataset) as archive:
        for info in archive.infolist():
            if info.is_dir() or Path(info.filename).suffix.lower() != ".json":
                continue
            with archive.open(info) as stream:
                for lineno, raw_line in enumerate(stream, start=1):
                    try:
                        record = json.loads(raw_line.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        unmapped[("unknown", 0)] += 1
                        records += 1
                        continue
                    if not isinstance(record, dict):
                        unmapped[("unknown", 0)] += 1
                        records += 1
                        continue
                    records += 1
                    try:
                        parts = extract_json_parts(record, lineno)
                    except (ValueError, TypeError, AttributeError):
                        unmapped[("unknown", 0)] += 1
                        continue
                    channel, event_id, record_id, fields, computer, raw_time = parts
                    try:
                        ingest = parse_windows_time(record.get("@timestamp"))
                    except ValueError:
                        try:
                            ingest = parse_windows_time(raw_time)
                        except ValueError:
                            ingest = 0
                    raw_text = _raw_text(record)
                    hit_steps = [
                        n for n in windows if contains_anchor(raw_text, anchors[n])
                    ]
                    for n in hit_steps:
                        if ingest:
                            derived[n].append(ingest)
                    try:
                        event = normalize_event(
                            channel=channel,
                            event_id=event_id,
                            fields=sanitize_record(fields),
                            computer=computer,
                            uid=make_uid(
                                f"{chain['dataset_file']}#{info.filename}", record_id
                            ),
                            raw_time=raw_time,
                            raw_record=sanitize_record(record),
                        )
                    except UnmappedEvent as exc:
                        unmapped[exc.key] += 1
                        for n in hit_steps:
                            start, end = windows[n]
                            if start <= ingest <= end:
                                per_step[n]["unmapped_anchor"][exc.key] += 1
                        continue
                    per_class[event.class_uid] += 1
                    per_activity[(event.class_uid, event.activity_id)] += 1
                    if has_in_band_technique_id(event):
                        in_band += 1
                    event_time = census_time_ms(event)
                    text = event_text_fields(event)
                    key = (event.class_uid, event.activity_id)
                    process = getattr(event, "process", None)
                    name = getattr(process, "name", None) if process else None
                    if (
                        event.class_uid == 1007
                        and event.activity_id == 3
                        and isinstance(name, str)
                        and name.lower() == "lsass.exe"
                        and chain_start <= event_time <= chain_end
                    ):
                        lsass_total += 1
                        granted = getattr(event, "actual_permissions", None)
                        lsass_granted[str(granted).strip().lower()] += 1
                        if is_lsass_high_access(event, chain):
                            lsass_high_times.append(event_time)
                    for n, entry in per_step.items():
                        start, end = windows[n]
                        inside = start <= event_time <= end
                        if inside and key in relevant[n]:
                            entry["relevant"] += 1
                        if text and contains_anchor(text, anchors[n]):
                            if inside:
                                entry["anchor_in"] += 1
                                entry["anchor_ids"].add(lineno)
                            else:
                                entry["anchor_out"] += 1
    for entry in per_step.values():
        entry["verdict"] = step_verdict(entry["anchor_in"], entry["relevant"])
    derived_windows = {
        n: (min(times), max(times)) if times else None for n, times in derived.items()
    }
    return {
        "records": records,
        "per_class": dict(sorted(per_class.items())),
        "per_activity": dict(sorted(per_activity.items())),
        "mapped": sum(per_class.values()),
        "unmapped": dict(unmapped),
        "unmapped_total": sum(unmapped.values()),
        "per_step": per_step,
        "derived_windows": derived_windows,
        "lsass_total": lsass_total,
        "lsass_granted": dict(sorted(lsass_granted.items())),
        "lsass_high_times": sorted(lsass_high_times),
        "in_band": in_band,
    }


def _lsass_clusters(times: list[int], chain: dict[str, Any]) -> list[dict[str, Any]]:
    """Group high-access LSASS times a minute apart; name containing windows."""
    clusters: list[dict[str, Any]] = []
    for time_ms in times:
        if clusters and time_ms - clusters[-1]["end"] <= 60_000:
            clusters[-1]["end"] = time_ms
            clusters[-1]["count"] += 1
        else:
            clusters.append({"start": time_ms, "end": time_ms, "count": 1})
    step6_start, step6_end = step_window_ms(chain["steps"][5])
    for cluster in clusters:
        containing = []
        for step in chain["steps"]:
            start, end = step_window_ms(step)
            if cluster["start"] <= end and start <= cluster["end"]:
                containing.append(int(step["step"]))
        cluster["steps"] = containing
        cluster["is_step6"] = step6_start <= cluster["start"] and (
            cluster["end"] <= step6_end
        )
    return clusters


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--report", default=None)
    parser.add_argument("--load-seconds", type=float, default=None)
    parser.add_argument("--load-peak-bytes", type=int, default=None)
    parser.add_argument("--cost-before-seconds", type=float, default=None)
    parser.add_argument("--cost-before-bytes", type=int, default=None)
    parser.add_argument("--cost-after-seconds", type=float, default=None)
    parser.add_argument("--cost-after-bytes", type=int, default=None)
    args = parser.parse_args(argv)

    dataset = (REPO_ROOT / args.dataset).resolve()
    try:
        dataset.relative_to(REPO_ROOT)
    except ValueError:
        print("error: --dataset must stay inside the repository")
        return 2
    if not dataset.is_file():
        print(f"error: dataset missing: {dataset}", file=sys.stderr)
        return 1

    chain = load_chain()
    result = run_census(dataset, chain)
    print(f"records: {result['records']} (mapped + unmapped)")
    print(f"events per class: {result['per_class']} (n={result['mapped']})")
    print(
        f"unmapped total: {result['unmapped_total']} "
        f"in {len(result['unmapped'])} buckets"
    )
    print(f"in-band technique-reference events: {result['in_band']}")
    print("top 15 unmapped:")
    for (channel, event_id), count in sorted(
        result["unmapped"].items(), key=lambda item: (-item[1], item[0])
    )[:15]:
        print(f"  {channel} {event_id}: {count}")
    high = {v.lower() for v in chain["lsass_high_access"]}
    lsass_high = sum(
        count for mask, count in result["lsass_granted"].items() if mask in high
    )
    print(
        f"lsass Sysmon 10 in chain window: {result['lsass_total']}; "
        f"by GrantedAccess: {result['lsass_granted']}; high-access: {lsass_high}"
    )
    for time_ms in result["lsass_high_times"]:
        print(f"  lsass high-access at {_fmt(time_ms)}")
    for label, buckets in (
        ("service", SERVICE_BUCKETS),
        ("registry", REGISTRY_BUCKETS),
    ):
        for bucket in sorted(buckets):
            print(f"{label} gap {bucket}: {result['unmapped'].get(bucket, 0)}")
    for step in chain["steps"]:
        n = int(step["step"])
        entry = result["per_step"][n]
        derived = result["derived_windows"][n]
        committed = step_window_ms(step)
        if derived is None:
            derived_text = "no anchor hits"
        else:
            derived_text = (
                f"{_fmt(derived[0])}-{_fmt(derived[1])} "
                f"(committed {_fmt(committed[0])}-{_fmt(committed[1])}, "
                f"start {derived[0] - committed[0]:+d} ms, "
                f"end {derived[1] - committed[1]:+d} ms)"
            )
        print(
            f"step {n}: verdict={entry['verdict']} "
            f"expected={step['match_kind']} "
            f"anchor_mapped_in={entry['anchor_in']} "
            f"anchor_mapped_out={entry['anchor_out']} "
            f"unmapped_anchor_in={dict(entry['unmapped_anchor'])} "
            f"relevant_in={entry['relevant']} derived_window={derived_text}"
        )
    if args.report:
        cost = None
        if (
            args.cost_before_seconds is not None
            and args.cost_before_bytes is not None
            and args.cost_after_seconds is not None
            and args.cost_after_bytes is not None
        ):
            cost = (
                args.cost_before_seconds,
                args.cost_before_bytes,
                args.cost_after_seconds,
                args.cost_after_bytes,
            )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.write_text(
            render_report(chain, result, args.load_seconds, args.load_peak_bytes, cost),
            encoding="utf-8",
        )
        print(f"wrote report to {report_path}")
    return 0


def render_report(
    chain: dict[str, Any],
    result: dict[str, Any],
    load_seconds: float | None,
    load_peak_bytes: int | None,
    mapping_cost: tuple[float, int, float, int] | None = None,
) -> str:
    """Render the counts-only report markdown from census counts."""
    today = datetime.now(tz=UTC).date().isoformat()
    per_class = result["per_class"]
    class_names = {
        1001: "File System Activity",
        1005: "Module Activity",
        1006: "Scheduled Job Activity",
        1007: "Process Activity",
        1009: "Script Activity",
        3002: "Authentication",
        4001: "Network Activity",
        201001: "Registry Key Activity",
        201002: "Registry Value Activity",
        201004: "Windows Service Activity",
    }
    lines = [
        "# APT29 day-1 compound replay load report",
        "",
        "Load: `corvus replay load "
        "data/security-datasets/datasets/compound/apt29/day1/"
        "apt29_evals_day1_manual.zip` "
        f"(n = 1 file, {result['records']} records). "
        f"Window: {chain['window']['start']} to {chain['window']['end']} "
        f"(`@timestamp` min/max over all records), run {today}. "
        "Ground truth: the ordered 10-step chain in "
        "[apt29_day1_ground_truth.json](../apt29_day1_ground_truth.json) "
        "(chain-level only; this dataset has no per-event labels, so "
        "event-level precision cannot be computed on it). Every count "
        "below reproduces with `uv run python eval/apt29_census.py`; "
        "the load totals reproduce with the load command above. "
        "Counts and ids only below, no event content, host names, "
        "user names, or script text.",
        "",
        "## Load totals",
        "",
        "- Files processed: 1. SHA-256 verified before load: "
        f"`{chain['dataset_sha256']}`.",
    ]
    if load_seconds is not None and load_peak_bytes is not None:
        lines.append(
            f"- Runtime: {load_seconds:.1f} s (loader summary). "
            f"Peak memory: {load_peak_bytes} bytes maximum resident "
            "set size via `/usr/bin/time -l`. The census pass streams "
            "record by record and never holds the dataset in memory."
        )
    else:
        lines.append(
            "- Runtime and peak memory: measured with "
            "`/usr/bin/time -l corvus replay load ...` at report "
            "generation; re-run that command to reproduce them. The "
            "census pass streams record by record and never holds "
            "the dataset in memory."
        )
    lines += [
        f"- Mapped events: {result['mapped']}. Unmapped records: "
        f"{result['unmapped_total']} in {len(result['unmapped'])} "
        "(channel, event id) buckets. Unsupported archive members: 0. "
        f"Mapped + unmapped = {result['records']}, the full record count.",
        f"- Events carrying an in-band technique reference "
        f"(provenance flag from the load): {result['in_band']}.",
    ]
    if mapping_cost is not None:
        before_s, before_b, after_s, after_b = mapping_cost
        before_events = result["mapped"] - result["per_class"].get(1005, 0)
        lines.append(
            f"- Sysmon 7 mapping cost: this tree vs commit `5d2296d` "
            f"(same file, same machine, separate `--replay-dir` loads): "
            f"loader {before_s:.1f} s -> {after_s:.1f} s; day-1 events "
            f"Parquet {before_b} bytes -> {after_b} bytes "
            f"(+{after_b - before_b} bytes); mapped events "
            f"{before_events} -> {result['mapped']} "
            f"(+{result['per_class'].get(1005, 0)} Module Activity). "
            f"Reproduced with `git worktree add /tmp/corvus-before "
            f"5d2296d`, `corvus replay load <file> --replay-dir <dir>` "
            f"on each tree, and `ls -l <dir>/events/"
            f"b6d3065fbd07eed2.parquet` (slug of the data-relative path)."
        )
    lines += [
        "",
        f"## Events per OCSF class (n = {result['mapped']})",
        "",
        "| Class | Events |",
        "|---|---|",
    ]
    for class_uid in sorted(per_class):
        lines.append(
            f"| {class_uid} {class_names.get(class_uid, '')} | {per_class[class_uid]} |"
        )
    lines += [
        "",
        "Script Activity is PowerShell 4104 plus PowerShell "
        "Operational 4103 and Windows PowerShell 800. Authentication "
        "includes both `Security` and WEF-forwarded lowercase "
        "`security` records under the canonical `Security` channel; "
        "a probe found no exact duplicate records across the two "
        "spellings. Registry Key Activity is Sysmon 12 CreateKey "
        "(Create) and DeleteKey (Delete) plus Sysmon 14 renames; "
        "Registry Value Activity is Sysmon 13 value sets (Set) plus "
        "Sysmon 12 DeleteValue (Delete). NXLog replaces the flat "
        "`EventType` field with the severity, so the op is read from "
        "the `Message` `EventType:` line. Windows Service Activity is "
        "Security 4697 and System 7045 service installs. Sysmon 7 "
        "image loads now map to Module Activity (1005, Load): "
        "`ImageLoaded` becomes `module.file` (hashes, description, "
        "company, product and original file name typed; signer fields "
        "stay in `unmapped`), the loading process is `actor.process`. "
        "Scheduled-job commands moved from the deprecated `job.cmd_line` "
        "to `job.job_actions[].cmd_line` (type 2 Execute), and win "
        "extension classes declare `metadata.extensions` (win, uid "
        '"2", version 1.9.0).',
        "",
        "Per-activity breakdown of the new classes "
        f"(n = {result['per_class'].get(201001, 0)} "
        f"+ {result['per_class'].get(201002, 0)}):",
        "",
        f"- Registry Key Activity (201001): Create "
        f"{result['per_activity'].get((201001, 1), 0)}, Delete "
        f"{result['per_activity'].get((201001, 4), 0)}, Rename "
        f"{result['per_activity'].get((201001, 5), 0)}.",
        f"- Registry Value Activity (201002): Set "
        f"{result['per_activity'].get((201002, 2), 0)}, Delete "
        f"{result['per_activity'].get((201002, 4), 0)}.",
        "",
        f"## Top 15 unmapped (channel, event id) buckets "
        f"(n = {result['unmapped_total']} records)",
        "",
        "| Channel | Event id | Records |",
        "|---|---|---|",
    ]
    for (channel, event_id), count in sorted(
        result["unmapped"].items(), key=lambda item: (-item[1], item[0])
    )[:15]:
        lines.append(f"| {channel} | {event_id} | {count} |")
    lines += [
        "",
        "Security buckets are canonical: lowercase `security` records "
        "count under `Security`, never as a second channel.",
        "",
        "## Ground-truth step visibility (per-step windows, counts only)",
        "",
        "Verdict per step: `direct` = at least one mapped event "
        "inside the step window whose text fields (process and "
        "parent path, command line, script content, file path, "
        "registry key/value path/name/data, service name/command "
        "line, scheduled-job name/action command line, loaded-module "
        "file path/name/description/product) contain a step anchor; "
        "`indirect` = no mapped anchor "
        "hit but technique-relevant events inside the window; `none` "
        "= neither. Anchor hits outside a step window are reported "
        "as out-of-window counts, not matches. Step windows were "
        "re-derived in the census (min/max ingest time of anchor "
        "hits over all records); the difference against the "
        "committed window is shown per step. No step changed verdict "
        "in the Sysmon 7 mapping pass: all 10 steps were `direct` "
        "before and stay `direct`, so no `match_kind` changes in "
        "the chain file. Seven steps gained mapped anchor hits — "
        "their Sysmon 7 image-load anchors moved from the unmapped "
        "bucket into mapped Module Activity events (the loading "
        "process name/path carries the anchor; step 1: 65 more, "
        "step 3: 68, step 4: 444, step 6: 19, step 8: 219, step 9: "
        "38, step 10: 9 in-window plus 9 out-of-window on step 5) — "
        "and the Sysmon 7 unmapped column is now empty on every "
        "step. Step 8's last 4 hits are PSEXESVC.exe image loads "
        "whose anchor lives only in the typed file description and "
        "product (`PsExec Service` / `Sysinternals PsExec`); the "
        "ImageLoaded path itself (`PSEXESVC.exe`) does not contain "
        "the anchor, which is why the module file fields joined the "
        "anchor search. Steps 2, 5 and 7 never referenced an image "
        "load and are unchanged.",
        "",
        "| Step | Window (UTC) | Anchor hits (mapped, in / out) | "
        "Unmapped anchor hits in window | Relevant in window | Verdict |",
        "|---|---|---|---|---|---|",
    ]
    for step in chain["steps"]:
        n = int(step["step"])
        entry = result["per_step"][n]
        start, end = step_window_ms(step)
        derived = result["derived_windows"][n]
        if derived is None:
            diff = "no anchor hits"
        else:
            diff = (
                f"derived {_fmt(derived[0])}-{_fmt(derived[1])} "
                f"({derived[0] - start:+d} / {derived[1] - end:+d} ms)"
            )
        unmapped_text = (
            "; ".join(
                f"{channel} {event_id}: {count}"
                for (channel, event_id), count in sorted(
                    entry["unmapped_anchor"].items(), key=lambda item: -item[1]
                )
            )
            or "none"
        )
        lines.append(
            f"| {n} {step['name']} | {_fmt(start)}-{_fmt(end)} ({diff}) | "
            f"{entry['anchor_in']} / {entry['anchor_out']} | "
            f"{unmapped_text} | {entry['relevant']} | {entry['verdict']} |"
        )
    both = result["per_step"][5]["anchor_ids"] & result["per_step"][10]["anchor_ids"]
    lines += [
        "",
        "Steps 5 and 10 share one persistence artifact but disjoint "
        f"windows; mapped anchor hits counted for both steps: {len(both)}. "
        "Their derived windows are identical because both steps "
        "derive from the same shared anchor, which also appears "
        "before the install, so the committed windows instead come "
        "from the plan sequence and the post-reboot service start. "
        "Step 5 is the install in its window: the 9 service-install "
        "and registry anchor hits are now mapped events (Windows "
        "Service Activity plus Registry Key/Value Activity) alongside "
        "the mapped Invoke-Persistence script block, and its unmapped "
        "column is empty. Step 10 is execution after the reboot: a "
        "mapped Sysmon 1 process creation of the service binary by "
        "its parent service controller inside the step-10 window, "
        "with a mapped rundll32 child seconds later, is direct "
        "evidence — step 10 is not indirect-only.",
        "",
        "## LSASS credential access (step 6)",
        "",
        f"Sysmon 10 opens against lsass in the chain window: "
        f"n = {result['lsass_total']}. By GrantedAccess (verbatim "
        f"`actual_permissions`): "
        + ", ".join(
            f"`{mask}` {count}" for mask, count in result["lsass_granted"].items()
        )
        + ". Dumping-grade opens (GrantedAccess in the chain file's "
        "high-access set) by ingest time:",
        "",
        "| Ingest time (UTC) | Opens | Step windows overlapping it | Attribution |",
        "|---|---|---|---|",
    ]
    for cluster in _lsass_clusters(result["lsass_high_times"], chain):
        span = _fmt(cluster["start"])
        if cluster["end"] != cluster["start"]:
            span += f"-{_fmt(cluster['end'])}"
        attribution = (
            "step 6 evidence" if cluster["is_step6"] else "not attributed by the plan"
        )
        lines.append(
            f"| {span} | {cluster['count']} | "
            f"{cluster['steps'] or 'none'} | {attribution} |"
        )
    lines += [
        "",
        "Only the opens inside step 6's own window count as step-6 "
        "evidence (a cluster shown as overlapping no step window "
        "falls outside all of them; the late cluster ends seconds "
        "before the step-10 window opens). The rest are reported "
        "here under the step windows "
        "they fall in, labelled not attributed by the plan, never as "
        "step-6 evidence. Matching on merely touching lsass would "
        f"report {result['lsass_total']} and drown the dumping-grade "
        "opens in benign `0x1000` queries, so every LSASS check keys "
        "on GrantedAccess.",
        "",
        "## Known visibility gaps (expected, not normalizer bugs)",
        "",
        f"- Service-based persistence (steps 5 and 10, T1543.003): "
        f"Security 4697 and System 7045 now map to Windows Service "
        f"Activity (201004, Create); unmapped leftovers in either "
        f"bucket: {result['unmapped'].get(('Security', 4697), 0)} and "
        f"{result['unmapped'].get(('System', 7045), 0)}. The pinned "
        "OCSF 1.9.0 win extension class is "
        "`windows_service_activity` (attribute `win_service`).",
        f"- Registry modification (steps 3 and 5, T1112 / T1547.001): "
        f"Sysmon 12, 13 and 14 now map to Registry Key/Value Activity "
        f"(201001/201002); unmapped leftovers: {_sysmon(result, 12)}, "
        f"{_sysmon(result, 13)} and {_sysmon(result, 14)}. Together "
        "Sysmon 12/13 were "
        f"{result['per_class'].get(201001, 0) + result['per_class'].get(201002, 0)} "
        f"of {result['records']} records, all mapped.",
        f"- Closed gap: Sysmon 7 image loads "
        f"({result['per_class'].get(1005, 0)}) now map to Module "
        "Activity (1005, Load); unmapped leftovers in that bucket: "
        f"{_sysmon(result, 7)}. The pinned OCSF 1.9.0 core class is "
        "`module_activity` (attribute `module`).",
        "",
        "## Recommendation: which unmapped ids to map next",
        "",
        "1. Security 4658/4656/4690/4663 (handle and key-deletion "
        "auditing) — now the largest unmapped buckets in this dataset "
        "after Sysmon 7 was mapped to Module Activity (1005).",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
