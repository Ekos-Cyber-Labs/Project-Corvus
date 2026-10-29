"""Census of prompt-injection signals over the replay store.

Usage (from the repo root)::

    uv run python eval/injection_census.py [--replay-dir data/replay]
        [--benign-dir data/replay-benign] [--every 20]

Reads events Parquet (``event_json`` column) from both stores, runs
``corvus.guardrails.injection.detect`` on every Nth event, and prints
COUNTS ONLY: events scanned, signals per pattern id, signals per
field path, events with at least one signal. No event content, host
or user names are printed (field paths name OCSF locations and JSON
envelope keys only, never values).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from corvus.guardrails.injection import detect

REPO_ROOT = Path(__file__).resolve().parent.parent


def scan_store(events_dir: Path, every: int) -> dict[str, Any]:
    """Run the detector over every Nth stored event; return counts only."""
    if every < 1:
        raise ValueError(f"--every must be >= 1, got {every}")
    by_pattern: Counter[str] = Counter()
    by_field: Counter[str] = Counter()
    scanned = 0
    flagged = 0
    files = 0
    for path in sorted(events_dir.glob("*.parquet")):
        files += 1
        column = pq.read_table(path, columns=["event_json"]).column("event_json")
        for index, raw in enumerate(column.to_pylist()):
            if index % every != 0:
                continue
            if not isinstance(raw, str):
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            scanned += 1
            signals = detect(event)
            if signals:
                flagged += 1
            for signal in signals:
                by_pattern[signal.pattern_id] += 1
                by_field[signal.field] += 1
    return {
        "files": files,
        "scanned": scanned,
        "flagged": flagged,
        "by_pattern": dict(sorted(by_pattern.items())),
        "by_field": dict(sorted(by_field.items())),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the census and print counts; return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-dir", default="data/replay")
    parser.add_argument("--benign-dir", default="data/replay-benign")
    parser.add_argument("--every", type=int, default=20)
    args = parser.parse_args(argv)

    replay_dir = (REPO_ROOT / args.replay_dir).resolve()
    benign_dir = (REPO_ROOT / args.benign_dir).resolve()
    try:
        replay_dir.relative_to(REPO_ROOT)
        benign_dir.relative_to(REPO_ROOT)
    except ValueError:
        print("error: store dirs must stay in the repo")
        return 2
    for store in (replay_dir / "events", benign_dir / "events"):
        if not store.is_dir():
            print(f"error: events store missing: {store}", file=sys.stderr)
            return 1

    attack = scan_store(replay_dir / "events", args.every)
    benign = scan_store(benign_dir / "events", args.every)
    total_scanned = attack["scanned"] + benign["scanned"]
    total_flagged = attack["flagged"] + benign["flagged"]
    print(f"every: {args.every}")
    print(f"attack store files: {attack['files']} (n={attack['scanned']})")
    print(f"benign store files: {benign['files']} (n={benign['scanned']})")
    print(f"events scanned: {total_scanned}")
    print(f"signals per pattern_id: {attack['by_pattern']} + {benign['by_pattern']}")
    print(f"signals per field: {attack['by_field']} + {benign['by_field']}")
    print(f"events with >=1 signal: {total_flagged}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
