"""Live replay-format store writer for the Wazuh poll.

The live store uses exactly the replay Parquet layouts
(:mod:`corvus.adapters.replay.schema`), so correlation reads it
with the same loaders. Provenance differs: replay provenance names
a dataset file and line, while live provenance names the indexer
and document id (``index`` + ``doc_id``). Writes are atomic (temp
file plus rename) and idempotent by uid: rows already present are
never rewritten, so re-running a cycle adds nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from corvus.adapters.replay.schema import (
    EVENTS_SCHEMA,
    FINDINGS_SCHEMA,
    event_to_row,
    finding_to_row,
)
from corvus.normalize.ocsf import DetectionFinding, OcsfEvent

__all__ = [
    "LIVE_PROVENANCE_SCHEMA",
    "append_live_records",
    "existing_uids",
    "live_provenance_dir",
]

#: Live provenance columns: uid plus the indexer and document id the
#: record came from (instead of a dataset file and line number).
LIVE_PROVENANCE_SCHEMA = pa.schema(
    [
        ("uid", pa.string()),
        ("index", pa.string()),
        ("doc_id", pa.string()),
    ]
)


def live_provenance_dir(store_dir: str | Path) -> Path:
    """Return the ``provenance/`` output directory under ``store_dir``."""
    return Path(store_dir) / "provenance"


def existing_uids(store_dir: str | Path, kind: str) -> set[str]:
    """Return the uids already stored under ``events`` or ``findings``."""
    directory = Path(store_dir) / kind
    if not directory.is_dir():
        return set()
    uids: set[str] = set()
    for path in sorted(directory.glob("*.parquet")):
        try:
            table = pq.read_table(path, columns=["uid"])
        except Exception:
            continue
        for record in table.to_pylist():
            uid = record.get("uid")
            if isinstance(uid, str) and uid:
                uids.add(uid)
    return uids


def _write_atomic(
    directory: Path, stem: str, schema: pa.Schema, rows: list[dict[str, Any]]
) -> int:
    """Write one Parquet file atomically; return the rows written."""
    if not rows:
        return 0
    directory.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=schema)
    tmp = directory / f"{stem}.tmp"
    final = directory / f"{stem}.parquet"
    pq.write_table(table, tmp)
    tmp.rename(final)
    return len(rows)


def append_live_records(
    store_dir: str | Path,
    events: list[tuple[OcsfEvent, str, str]],
    findings: list[tuple[DetectionFinding, str, str, str, str]],
    stem: str,
) -> dict[str, int]:
    """Append new live records; return ``{events, findings}`` written.

    ``events`` holds ``(event, index, doc_id)`` triples and
    ``findings`` holds ``(finding, rule_id, level, index, doc_id)``
    tuples. Rows whose uid is already stored are skipped, so the
    same cycle run twice writes nothing the second time. Provenance
    rows are written for the same new uids only.
    """
    root = Path(store_dir)
    known_events = existing_uids(root, "events")
    known_findings = existing_uids(root, "findings")
    event_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    provenance_rows: list[dict[str, Any]] = []
    for event, index, doc_id in events:
        uid = event.metadata.uid or ""
        if not uid or uid in known_events:
            continue
        known_events.add(uid)
        event_rows.append(event_to_row(event))
        provenance_rows.append({"uid": uid, "index": index, "doc_id": doc_id})
    for finding, rule_id, level, index, doc_id in findings:
        uid = finding.metadata.uid or ""
        if not uid or uid in known_findings:
            continue
        known_findings.add(uid)
        finding_rows.append(finding_to_row(finding, rule_id, level))
        provenance_rows.append({"uid": uid, "index": index, "doc_id": doc_id})
    wrote_events = _write_atomic(
        root / "events", f"{stem}-events", EVENTS_SCHEMA, event_rows
    )
    wrote_findings = _write_atomic(
        root / "findings", f"{stem}-findings", FINDINGS_SCHEMA, finding_rows
    )
    _write_atomic(
        live_provenance_dir(root),
        f"{stem}-provenance",
        LIVE_PROVENANCE_SCHEMA,
        provenance_rows,
    )
    return {"events": wrote_events, "findings": wrote_findings}
