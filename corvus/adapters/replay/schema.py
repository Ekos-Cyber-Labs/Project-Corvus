"""Parquet layouts for the replay store (explicit schemas, never inferred).

``data/replay/`` holds one ``events/<slug>.parquet`` plus one
``provenance/<slug>.parquet`` per loaded dataset file (``slug`` is the
opaque hex of the data-relative path, so file names carrying technique
ids never appear on disk either). The events table carries the OCSF
record plus the flat columns DuckDB filters on; the provenance table
carries the dataset path and the in-band-technique flag keyed by event
uid. Only the eval harness reads provenance; the adapter never does.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pyarrow as pa

if TYPE_CHECKING:
    from corvus.normalize.ocsf import OcsfEvent

__all__ = [
    "EVENTS_SCHEMA",
    "PROVENANCE_SCHEMA",
    "event_to_row",
    "provenance_to_row",
    "slug_for_rel",
]

#: Flat event columns DuckDB filters and groups on, plus the full record.
EVENTS_SCHEMA = pa.schema(
    [
        ("uid", pa.string()),
        ("time", pa.int64()),
        ("class_uid", pa.int32()),
        ("category_uid", pa.int32()),
        ("activity_id", pa.int32()),
        ("severity_id", pa.int32()),
        ("product", pa.string()),
        ("log_name", pa.string()),
        ("host", pa.string()),
        ("user", pa.string()),
        ("ip", pa.string()),
        ("src_ip", pa.string()),
        ("dst_ip", pa.string()),
        ("event_json", pa.string()),
    ]
)

#: Provenance columns: join key, data-relative path, dataset, flag.
PROVENANCE_SCHEMA = pa.schema(
    [
        ("uid", pa.string()),
        ("file", pa.string()),
        ("dataset", pa.string()),
        ("in_band_technique_id", pa.bool_()),
    ]
)


def slug_for_rel(data_rel: str) -> str:
    """Return the opaque output slug for one data-relative dataset path."""
    return hashlib.sha256(data_rel.encode("utf-8")).hexdigest()[:16]


def dataset_for_rel(data_rel: str) -> str:
    """Return the dataset name (first path segment) for a data-relative path."""
    return data_rel.split("/", 1)[0] if "/" in data_rel else data_rel


def event_to_row(event: OcsfEvent) -> dict[str, Any]:
    """Flatten one OCSF event to an events-table row (no provenance)."""
    keys = event.entity_keys
    return {
        "uid": event.metadata.uid,
        "time": event.time,
        "class_uid": event.class_uid,
        "category_uid": event.category_uid,
        "activity_id": event.activity_id,
        "severity_id": event.severity_id,
        "product": event.metadata.product.name,
        "log_name": event.metadata.log_name,
        "host": keys.host,
        "user": keys.user,
        "ip": keys.ip,
        "src_ip": keys.src_ip,
        "dst_ip": keys.dst_ip,
        "event_json": event.model_dump_json(),
    }


def provenance_to_row(
    uid: str, data_rel: str, in_band_technique_id: bool
) -> dict[str, Any]:
    """Build one provenance row: uid, data-relative path, dataset, flag."""
    return {
        "uid": uid,
        "file": data_rel,
        "dataset": dataset_for_rel(data_rel),
        "in_band_technique_id": in_band_technique_id,
    }


def events_dir(replay_dir: str | Path) -> Path:
    """Return the ``events/`` output directory under ``replay_dir``."""
    return Path(replay_dir) / "events"


def provenance_dir(replay_dir: str | Path) -> Path:
    """Return the ``provenance/`` output directory under ``replay_dir``."""
    return Path(replay_dir) / "provenance"
