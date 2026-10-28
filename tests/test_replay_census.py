"""Tests for eval/replay_census.py on a tiny synthetic replay store.

All paths, labels, and rows below are hand-written fakes; no real
dataset content is used, and no host or user names appear anywhere.
"""

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from corvus.adapters.replay.schema import (
    EVENTS_SCHEMA,
    PROVENANCE_SCHEMA,
    slug_for_rel,
)
from eval.replay_census import (
    events_per_class,
    file_census,
    load_ground_truth,
    provenance_stats,
    summarize,
)

LABELS = {
    "synth-a/f1.evtx": {
        "dataset": "synth-a",
        "techniques": ["T1003"],
        "tactics": ["Credential Access"],
        "label_source": "otrf-metadata",
    },
    "synth-a/f2.evtx": {
        "dataset": "synth-a",
        "techniques": [],
        "tactics": ["Execution"],
        "label_source": "otrf-folder",
    },
    "synth-b/f3.evtx": {
        "dataset": "synth-b",
        "techniques": ["T1059"],
        "tactics": ["Execution"],
        "label_source": "otrf-metadata",
    },
    "synth-a/f4.evtx": {
        "dataset": "synth-a",
        "techniques": [],
        "tactics": [],
        "label_source": "evtx-folder",
    },
}


def _event_row(uid: str, class_uid: int) -> dict[str, object]:
    """Build one minimal events-table row (no event content)."""
    return {
        "uid": uid,
        "time": 1700000000000,
        "class_uid": class_uid,
        "category_uid": 1,
        "activity_id": 1,
        "severity_id": 1,
        "product": "synth",
        "log_name": "synth",
        "host": None,
        "user": None,
        "ip": None,
        "src_ip": None,
        "dst_ip": None,
        "event_json": "{}",
    }


def _write_fixture_store(root: Path) -> None:
    """Write a four-key fixture store: two files with events, one empty."""
    events = root / "events"
    prov = root / "provenance"
    events.mkdir(parents=True)
    prov.mkdir(parents=True)
    rows = {
        "synth-a/f1.evtx": [
            (_event_row("uid-1", 1007), True),
            (_event_row("uid-2", 1007), False),
        ],
        "synth-a/f2.evtx": [(_event_row("uid-3", 3002), False)],
        "synth-a/f4.evtx": [],
        # synth-b/f3.evtx is never loaded: no Parquet pair at all.
    }
    for rel, items in rows.items():
        slug = slug_for_rel(rel)
        pq.write_table(
            pa.table(
                {name: [row[name] for row, _ in items] for name in EVENTS_SCHEMA.names},
                schema=EVENTS_SCHEMA,
            ),
            events / f"{slug}.parquet",
        )
        pq.write_table(
            pa.table(
                {
                    "uid": [row["uid"] for row, _ in items],
                    "file": [rel] * len(items),
                    "dataset": [rel.split("/")[0]] * len(items),
                    "in_band_technique_id": [flag for _, flag in items],
                },
                schema=PROVENANCE_SCHEMA,
            ),
            prov / f"{slug}.parquet",
        )


def test_census_fixture_store(tmp_path: Path) -> None:
    store = tmp_path / "replay"
    _write_fixture_store(store)

    census = file_census(store, LABELS)
    assert census["synth-a/f1.evtx"]["loaded"] is True
    assert census["synth-a/f1.evtx"]["events"] == 2
    assert census["synth-a/f1.evtx"]["in_band"] is True
    assert census["synth-a/f2.evtx"]["in_band"] is False
    assert census["synth-b/f3.evtx"]["loaded"] is False
    assert census["synth-b/f3.evtx"]["events"] == 0
    assert census["synth-a/f4.evtx"]["loaded"] is True
    assert census["synth-a/f4.evtx"]["events"] == 0

    summary = summarize(census)
    assert summary["keys"] == 4
    assert summary["never"] == {("synth-b", "otrf-metadata"): 1}
    assert summary["never_suffix"] == {("synth-b", "otrf-metadata", ".evtx"): 1}
    assert summary["empty"] == {("synth-a", "evtx-folder"): 1}
    assert summary["mapped_events"] == 3
    assert summary["techniques"] == (2, 1, ["T1059"])
    assert summary["tactics"] == (2, 2, [])
    assert summary["in_band_files"] == {"synth-a": 1}

    assert events_per_class(store) == {1007: 2, 3002: 1}
    assert provenance_stats(store) == {
        "synth-a": {"files": 2, "events": 3, "in_band": 1},
    }


def test_load_ground_truth_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "ground_truth.json"
    path.write_text(json.dumps(LABELS), encoding="utf-8")
    assert load_ground_truth(path) == LABELS
