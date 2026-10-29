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
    from corvus.normalize.ocsf import DetectionFinding, OcsfEvent

__all__ = [
    "EVENTS_SCHEMA",
    "FINDINGS_SCHEMA",
    "PROVENANCE_SCHEMA",
    "event_to_row",
    "finding_to_row",
    "findings_dir",
    "provenance_to_row",
    "serialize_ocsf",
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

#: Findings columns: one Detection Finding (2004) per row, queryable
#: without parsing the JSON. Written by the replay detect run, one
#: file per input slug, rewritten atomically like the event files.
FINDINGS_SCHEMA = pa.schema(
    [
        ("uid", pa.string()),
        ("time", pa.int64()),
        ("class_uid", pa.int32()),
        ("rule_id", pa.string()),
        ("level", pa.string()),
        ("host", pa.string()),
        ("finding_json", pa.string()),
    ]
)


def slug_for_rel(data_rel: str) -> str:
    """Return the opaque output slug for one data-relative dataset path."""
    return hashlib.sha256(data_rel.encode("utf-8")).hexdigest()[:16]


def dataset_for_rel(data_rel: str) -> str:
    """Return the dataset name (first path segment) for a data-relative path."""
    return data_rel.split("/", 1)[0] if "/" in data_rel else data_rel


def serialize_ocsf(event: OcsfEvent) -> str:
    """Serialize one OCSF record exactly as the store keeps it.

    Drops ``None``-valued typed fields at every nesting level
    alongside the Corvus-internal ``entity_keys``, so a null-valued
    name the class does not define can never hide in the stored JSON.
    The free-form ``unmapped`` object is the one exception: it keeps
    ``None`` values verbatim as logged (1,168 stored Script Activity
    records carry ``unmapped`` ``UserData``, ``Path`` or ``Binary`` as
    null), because it records what the source logged, nulls included.
    Readers only ever ``.get()`` stored fields (or revalidate with
    pydantic), and ``raw_data`` placeholders such as ``"-"`` are
    strings, so omitting typed nulls changes no value the detector
    reads; reading a stored record back revalidates and recomputes
    ``entity_keys``.
    """
    return event.model_dump_json(exclude={"entity_keys"}, exclude_none=True)


def event_to_row(event: OcsfEvent) -> dict[str, Any]:
    """Flatten one OCSF event to an events-table row (no provenance).

    ``entity_keys`` is Corvus-internal, not an OCSF attribute: the keys
    travel as the flat ``host``/``user``/``ip``/``src_ip``/``dst_ip``
    columns and are recomputed on read, so the stored ``event_json``
    excludes them and validates against the schema as written.
    """
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
        "event_json": serialize_ocsf(event),
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


def findings_dir(replay_dir: str | Path) -> Path:
    """Return the ``findings/`` output directory under ``replay_dir``."""
    return Path(replay_dir) / "findings"


def finding_to_row(
    finding: DetectionFinding, rule_id: str, level: str
) -> dict[str, Any]:
    """Flatten one Detection Finding to a findings-table row.

    As in :func:`event_to_row`, the Corvus-internal ``entity_keys``
    travel as the flat ``host`` column and are recomputed on read, so
    the stored ``finding_json`` excludes them.
    """
    return {
        "uid": finding.metadata.uid,
        "time": finding.time,
        "class_uid": finding.class_uid,
        "rule_id": rule_id,
        "level": level,
        "host": finding.entity_keys.host,
        "finding_json": serialize_ocsf(finding),
    }
