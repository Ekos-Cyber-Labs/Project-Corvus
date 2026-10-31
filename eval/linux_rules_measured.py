"""Measure the shipped Linux Sigma rules (report only, no engine changes).

Usage (from the repo root)::

    uv run python eval/linux_rules_measured.py

Extracts ``rules/linux/*`` from ``data/sigma/sigma_all_rules.zip`` into a
temporary directory (never into ``data/sigma/rules``, so the Windows
harness is untouched), loads them with the same status gate the engine
uses for Windows (``test`` + ``stable``), evaluates them over the
benign baseline store and the attack-chain store with the same engine
and mapping as production, and writes
``eval/reports/linux_rules_measured.md``.

Every published number carries its n, window, and this producing
command. Counts and rule ids only, never event content.
"""

from __future__ import annotations

import glob
import json
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pyarrow.parquet as pq

REPO = Path(__file__).resolve().parent.parent
SIGMA_ZIP = REPO / "data" / "sigma" / "sigma_all_rules.zip"
BASELINE_DIR = REPO / "data" / "replay-linux-baseline"
CHAIN_DIR = REPO / "data" / "replay-linux-chain1"
GROUND_TRUTH = REPO / "data" / "lab-chain1" / "ground_truth_cadena1.jsonl"
REPORT_PATH = REPO / "eval" / "reports" / "linux_rules_measured.md"

PRODUCING_COMMAND = "uv run python eval/linux_rules_measured.py"


def ms_from_iso(moment: str) -> int:
    """Parse an ISO-8601 UTC instant to epoch milliseconds."""
    return int(datetime.fromisoformat(moment.replace("Z", "+00:00")).timestamp() * 1000)


def iso_from_ms(moment_ms: int) -> str:
    """Render epoch milliseconds as an ISO-8601 UTC instant."""
    return datetime.fromtimestamp(moment_ms / 1000, tz=UTC).isoformat()


def store_times(replay_dir: Path) -> list[int]:
    """Return every event time in the store (for n and the window)."""
    times: list[int] = []
    for path in sorted(glob.glob(str(replay_dir / "events" / "*.parquet"))):
        times.extend(pq.read_table(path, columns=["time"]).column("time").to_pylist())
    return times


def main() -> None:
    from corvus.detect.engine import evaluate
    from corvus.detect.rules import load_rules

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="lnx-rules") as tmp:
        tmpdir = Path(tmp)
        with zipfile.ZipFile(SIGMA_ZIP) as bundle:
            names = [
                name for name in bundle.namelist() if name.startswith("rules/linux/")
            ]
            for name in names:
                target = tmpdir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(bundle.read(name))
        compiled, stats = load_rules(tmpdir / "rules" / "linux")
        matches_base, _, eval_base = evaluate(BASELINE_DIR, compiled)
        matches_chain, _, eval_chain = evaluate(CHAIN_DIR, compiled)

    steps = [
        json.loads(line)
        for line in GROUND_TRUTH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    windows = [
        (
            step["step"],
            step["technique"],
            ms_from_iso(step["start"]),
            ms_from_iso(step["end"]),
        )
        for step in steps
    ]
    chain_times: dict[str, int] = {}
    for path in sorted(glob.glob(str(CHAIN_DIR / "events" / "*.parquet"))):
        for row in pq.read_table(path, columns=["uid", "time"]).to_pylist():
            chain_times[row["uid"]] = row["time"]

    base_times = store_times(BASELINE_DIR)
    chain_all = store_times(CHAIN_DIR)
    base_window = (min(base_times), max(base_times))
    chain_window = (min(chain_all), max(chain_all))

    rows = []
    for rule in sorted(compiled, key=lambda item: item.rule_id):
        base_hits = sorted(matches_base.get(rule.rule_id, set()))
        chain_hits = sorted(matches_chain.get(rule.rule_id, set()))
        step_hits = sorted(
            {
                str(number)
                for uid in chain_hits
                for number, _, start, end in windows
                if uid in chain_times and start <= chain_times[uid] <= end
            },
            key=int,
        )
        rows.append(
            {
                "title": rule.title,
                "rule_id": rule.rule_id,
                "level": rule.level,
                "group": rule.group,
                "file": rule.rel_path,
                "baseline": len(base_hits),
                "chain": len(chain_hits),
                "steps": step_hits,
            }
        )

    covered = sorted({step for row in rows for step in row["steps"]}, key=int)
    uncovered = [
        str(number) for number, _, _, _ in windows if str(number) not in covered
    ]

    lines = [
        "# Linux shipped-rule measurement",
        "",
        "Date: 2026-10-30 (maintainer local, UTC-6). "
        f"Producing command: `{PRODUCING_COMMAND}` "
        "(run from the repo root; every number carries its n).",
        "",
        "## Rule inventory",
        "",
        f"`data/sigma/sigma_all_rules.zip` holds {len(names)} "
        f"`rules/linux/*.yml` rules (n={len(names)}, counted from the zip). "
        f"Loaded with the same status gate as Windows (`test` + `stable`): "
        f"{stats.evaluated} evaluate (n={stats.evaluated}), "
        f"{sum(stats.skipped.values())} skipped "
        f"(n={sum(stats.skipped.values())}).",
        "",
        "Skip buckets (first hit wins, same order as the Windows report):",
        "",
    ]
    for reason in (
        "status",
        "logsource",
        "event_id",
        "unmapped_field",
        "unsupported_construct",
    ):
        detail = stats.skip_details.get(reason, {})
        if detail:
            lines.append(f"- `{reason}` {stats.skipped.get(reason, 0)}:")
            for key in sorted(detail):
                lines.append(f"  - {detail[key]} x `{key}`")
    lines += [
        "",
        "The auditd-service rules and the syslog/sshd/cron keyword rules "
        "stay out of scope; they remain counted under `logsource` above. "
        "Rules using an unmapped field (`ParentImage`, "
        "`ParentCommandLine`, `CurrentDirectory`, `Image` on file/network "
        "rows, `Initiated`, `DestinationHostname`) are skipped and counted "
        "under `unmapped_field`, never evaluated against null.",
        "",
        "## False positives on the benign baseline",
        "",
        f"Window {iso_from_ms(base_window[0])}..{iso_from_ms(base_window[1])}, "
        f"n={len(base_times)} events. "
        f"{eval_base.matches} matches on {eval_base.events_matched} events "
        f"(n={eval_base.matches} matches, n={eval_base.events_matched} events).",
        "",
        "| rule id | title | level | baseline hits |",
        "|---|---|---|---|",
    ]
    firing_base = [row for row in rows if row["baseline"]]
    if firing_base:
        for row in sorted(firing_base, key=lambda item: -item["baseline"]):
            lines.append(
                f"| `{row['rule_id']}` | {row['title']} "
                f"| {row['level']} | {row['baseline']} |"
            )
    else:
        lines.append("| (none) | | | |")
    lines += [
        "",
        "## Chain coverage",
        "",
        f"Window {iso_from_ms(chain_window[0])}..{iso_from_ms(chain_window[1])}, "
        f"n={len(chain_all)} events. "
        f"{eval_chain.matches} matches on {eval_chain.events_matched} events "
        f"(n={eval_chain.matches} matches, n={eval_chain.events_matched} events).",
        "",
        "| rule id | title | level | chain hits | step windows |",
        "|---|---|---|---|---|",
    ]
    firing_chain = [row for row in rows if row["chain"]]
    if firing_chain:
        for row in sorted(firing_chain, key=lambda item: -item["chain"]):
            steps_cell = (
                ", ".join(row["steps"])
                if row["steps"]
                else "(outside every step window)"
            )
            lines.append(
                f"| `{row['rule_id']}` | {row['title']} "
                f"| {row['level']} | {row['chain']} | {steps_cell} |"
            )
    else:
        lines.append("| (none) | | | | |")
    lines += [
        "",
        "## Uncovered chain steps",
        "",
        f"Steps with no firing shipped rule inside their window: "
        f"{', '.join(uncovered) if uncovered else '(none)'} "
        f"(n={len(uncovered)} of {len(windows)} steps).",
        "",
    ]
    for number, technique, start, end in windows:
        in_window = "covered" if str(number) in covered else "UNCOVERED"
        lines.append(
            f"- step {number} ({technique}, "
            f"{iso_from_ms(start)}..{iso_from_ms(end)}): {in_window}"
        )
    lines += [
        "",
        f"Evaluated in {time.monotonic() - started:.1f} s wall.",
        "",
    ]
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {REPORT_PATH} ({len(rows)} rules)")


if __name__ == "__main__":
    main()
