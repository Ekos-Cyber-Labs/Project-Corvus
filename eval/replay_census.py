"""Census of a replay load: provenance joined to data/ground_truth.json.

Usage (from the repo root, after ``corvus replay load data``)::

    uv run python eval/replay_census.py [--replay-dir data/replay]
        [--ground-truth data/ground_truth.json]

Reads the replay store (events plus provenance Parquet) and the
ground-truth mapping; prints counts only (no event content, no host or
user names). Unmapped ``(channel, event id)`` buckets are not in the
store (it keeps mapped events only); those counts come from the
``corvus replay load`` summary printed at load time.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from corvus.adapters.replay.schema import slug_for_rel

REPO_ROOT = Path(__file__).resolve().parent.parent

OTRF_METADATA_SOURCE = "otrf-metadata"


def load_ground_truth(path: Path) -> dict[str, dict[str, Any]]:
    """Read the ground-truth mapping (data-relative path to label object)."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"ground truth at {path} is not a JSON object")
    return raw


def file_census(
    replay_dir: Path, ground_truth: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Join every ground-truth key to its replay store rows.

    Returns per-key ``loaded`` (events Parquet present), ``events``
    (mapped row count), ``in_band`` (any provenance row flagged), plus
    the label fields. Keys with no Parquet are never-loaded; loaded
    keys with zero rows were loaded but mapped nothing.
    """
    events_dir = replay_dir / "events"
    prov_dir = replay_dir / "provenance"
    census: dict[str, dict[str, Any]] = {}
    for rel, label in ground_truth.items():
        slug = slug_for_rel(rel)
        events_path = events_dir / f"{slug}.parquet"
        prov_path = prov_dir / f"{slug}.parquet"
        loaded = events_path.is_file()
        events = pq.read_metadata(events_path).num_rows if loaded else 0
        in_band = False
        if prov_path.is_file():
            flags = (
                pq.read_table(prov_path, columns=["in_band_technique_id"])
                .column("in_band_technique_id")
                .to_pylist()
            )
            in_band = any(flags)
        census[rel] = {
            "loaded": loaded,
            "events": events,
            "in_band": in_band,
            "dataset": label.get("dataset"),
            "label_source": label.get("label_source"),
            "techniques": list(label.get("techniques", [])),
            "tactics": list(label.get("tactics", [])),
        }
    return census


def events_per_class(replay_dir: Path) -> dict[int, int]:
    """Count stored events per OCSF class (one file at a time)."""
    counts: Counter[int] = Counter()
    for path in sorted((replay_dir / "events").glob("*.parquet")):
        counts.update(
            pq.read_table(path, columns=["class_uid"]).column("class_uid").to_pylist()
        )
    return dict(sorted(counts.items()))


def summarize(
    census: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate a per-key census into report counts."""
    by_source: Counter[tuple[Any, Any]] = Counter()
    never: Counter[tuple[Any, Any]] = Counter()
    never_suffix: Counter[tuple[Any, Any, Any]] = Counter()
    empty: Counter[tuple[Any, Any]] = Counter()
    in_band_files: Counter[Any] = Counter()
    tech_hit: dict[str, bool] = {}
    tactic_hit: dict[str, bool] = {}
    for rel, row in census.items():
        key = (row["dataset"], row["label_source"])
        by_source[key] += 1
        if not row["loaded"]:
            never[key] += 1
            never_suffix[
                (row["dataset"], row["label_source"], Path(rel).suffix.lower())
            ] += 1
            for technique in row["techniques"]:
                tech_hit.setdefault(technique, False)
            continue
        if row["events"] == 0:
            empty[key] += 1
        if row["in_band"]:
            in_band_files[row["dataset"]] += 1
        for technique in row["techniques"]:
            if row["label_source"] == OTRF_METADATA_SOURCE:
                tech_hit[technique] = (
                    tech_hit.get(technique, False) or row["events"] > 0
                )
        for tactic in row["tactics"]:
            tactic_hit[tactic] = tactic_hit.get(tactic, False) or row["events"] > 0
    return {
        "keys": len(census),
        "by_source": dict(sorted(by_source.items())),
        "never": dict(sorted(never.items())),
        "never_suffix": dict(sorted(never_suffix.items())),
        "empty": dict(sorted(empty.items())),
        "mapped_events": sum(row["events"] for row in census.values()),
        "techniques": (
            len(tech_hit),
            sum(tech_hit.values()),
            sorted(t for t, h in tech_hit.items() if not h),
        ),
        "tactics": (
            len(tactic_hit),
            sum(tactic_hit.values()),
            sorted(t for t, h in tactic_hit.items() if not h),
        ),
        "in_band_files": dict(sorted(in_band_files.items())),
    }


def provenance_stats(replay_dir: Path) -> dict[str, dict[str, int]]:
    """Count provenance rows per dataset (files, events, in-band events)."""
    stats: dict[str, dict[str, Any]] = {}
    for path in sorted((replay_dir / "provenance").glob("*.parquet")):
        table = pq.read_table(path, columns=["file", "dataset", "in_band_technique_id"])
        for file, dataset, flag in zip(
            table.column("file").to_pylist(),
            table.column("dataset").to_pylist(),
            table.column("in_band_technique_id").to_pylist(),
            strict=True,
        ):
            entry = stats.setdefault(
                dataset, {"files": set(), "events": 0, "in_band": 0}
            )
            entry["files"].add(file)
            entry["events"] += 1
            entry["in_band"] += 1 if flag else 0
    return {
        dataset: {
            "files": len(entry["files"]),
            "events": entry["events"],
            "in_band": entry["in_band"],
        }
        for dataset, entry in sorted(stats.items())
    }


def main(argv: list[str] | None = None) -> int:
    """Run the census and print counts; return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-dir", default="data/replay")
    parser.add_argument("--ground-truth", default="data/ground_truth.json")
    args = parser.parse_args(argv)

    replay_dir = (REPO_ROOT / args.replay_dir).resolve()
    truth_path = (REPO_ROOT / args.ground_truth).resolve()
    try:
        replay_dir.relative_to(REPO_ROOT)
        truth_path.relative_to(REPO_ROOT)
    except ValueError:
        print("error: --replay-dir and --ground-truth must stay in the repo")
        return 2
    if not replay_dir.is_dir():
        print(f"error: replay store missing: {replay_dir}", file=sys.stderr)
        return 1
    if not truth_path.is_file():
        print(f"error: ground truth missing: {truth_path}", file=sys.stderr)
        return 1

    ground_truth = load_ground_truth(truth_path)
    census = file_census(replay_dir, ground_truth)
    summary = summarize(census)
    per_class = events_per_class(replay_dir)
    by_dataset = provenance_stats(replay_dir)

    tech_total, tech_hit, tech_miss = summary["techniques"]
    tactic_total, tactic_hit, tactic_miss = summary["tactics"]
    print(f"keys: {summary['keys']}")
    print(f"by (dataset, label_source): {summary['by_source']}")
    print(f"never loaded: {summary['never']}")
    print(f"never loaded by suffix: {summary['never_suffix']}")
    print(f"zero mapped: {summary['empty']}")
    print(f"events per class: {per_class} (n={summary['mapped_events']})")
    print(
        f"otrf-metadata techniques with a mapped event: "
        f"{tech_hit} of {tech_total}; without: {tech_miss}"
    )
    print(
        f"tactics with a mapped event: "
        f"{tactic_hit} of {tactic_total}; without: {tactic_miss}"
    )
    print(f"provenance by dataset: {by_dataset}")
    print(f"in-band files by dataset: {summary['in_band_files']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
