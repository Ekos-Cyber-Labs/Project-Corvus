"""Load dataset files into the replay Parquet store.

:func:`load_path` accepts one dataset file or a directory (discovered
recursively, sorted), streams each file through
:func:`corvus.normalize.windows.iter_dataset_file` in batches so the
multi-stage chain dataset never sits fully in memory, and writes one
``events/<slug>.parquet`` plus one ``provenance/<slug>.parquet`` per
input file (rewritten, so re-loads are idempotent). Provenance keeps the
data-relative path exactly as the keys of ``data/ground_truth.json``
(``eval/ground_truth.py``); only the eval harness reads it back.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from corvus.adapters.replay.schema import (
    EVENTS_SCHEMA,
    PROVENANCE_SCHEMA,
    event_to_row,
    events_dir,
    provenance_dir,
    provenance_to_row,
    slug_for_rel,
)
from corvus.normalize.technique_ids import has_in_band_technique_id
from corvus.normalize.windows import WindowsReadStats, iter_dataset_file

__all__ = [
    "BATCH_SIZE",
    "LoadSummary",
    "data_relative",
    "discover_dataset_files",
    "format_summary",
    "load_path",
]

#: Rows buffered before one Parquet write (bounds loader memory).
BATCH_SIZE = 5000


@dataclass
class LoadSummary:
    """Counts for one :func:`load_path` run (printed by the CLI)."""

    files_loaded: int = 0
    files_empty: int = 0
    events_total: int = 0
    per_class: dict[int, int] = field(default_factory=dict)
    unmapped: dict[tuple[str, int], int] = field(default_factory=dict)
    unsupported: int = 0
    seconds: float = 0.0
    in_band_events: int = 0
    in_band_files: int = 0


def _supported_suffix(path: Path) -> bool:
    """Return True for ``.evtx`` / ``.json`` / ``.zip`` / ``.tar.gz`` / ``.tgz``."""
    if path.suffix.lower() in {".evtx", ".json"}:
        return True
    if path.suffix.lower() in {".zip", ".tgz"}:
        return True
    return path.suffixes[-2:] == [".tar", ".gz"]


def discover_dataset_files(source: Path) -> list[Path]:
    """List dataset files under ``source`` (a file or directory), sorted.

    A direct file with an unsupported suffix raises; directory scans skip
    non-dataset files (checksums, ground truth) silently. Directory scans
    also skip bare ``.json`` files: OTRF ships some payloads both zipped
    and bare (byte-identical), and the metadata links only the archive,
    so loading both would duplicate the events with new uids. Pass a
    ``.json`` path directly to load it explicitly.
    """
    if source.is_file():
        if not _supported_suffix(source):
            raise ValueError(f"unsupported dataset file suffix for {source}")
        return [source]
    found = [
        path
        for path in sorted(source.rglob("*"))
        if path.is_file() and _supported_suffix(path) and path.suffix.lower() != ".json"
    ]
    return found


def data_relative(path: Path, data_dir: Path) -> str:
    """Return ``path`` relative to ``data_dir`` as a posix string.

    Raises when ``path`` is not under ``data_dir``: a bare file name
    would silently break the ground-truth join, and a later reload under
    the right root would duplicate the events with new uids. Resolved on
    both sides so symlinked temporary directories still join.
    """
    try:
        return path.resolve().relative_to(data_dir.resolve()).as_posix()
    except ValueError:
        raise ValueError(
            f"{path} is outside the dataset root {data_dir}; provenance "
            "paths must stay data-relative so they join data/ground_truth.json"
        ) from None


def _write_rows(
    writer: pq.ParquetWriter,
    schema: pa.Schema,
    rows: list[dict[str, Any]],
) -> None:
    """Write buffered rows with the explicit schema and drain the buffer."""
    table = pa.table(
        {
            name: pa.array(
                [row.get(name) for row in rows], type=schema.field(name).type
            )
            for name in schema.names
        }
    )
    writer.write_table(table)
    rows.clear()


def load_path(
    source: str | Path,
    *,
    replay_dir: str | Path = "data/replay",
    data_dir: str | Path = "data",
    batch_size: int = BATCH_SIZE,
) -> LoadSummary:
    """Normalize ``source`` into Parquet under ``replay_dir``; return counts."""
    started = time.monotonic()
    summary = LoadSummary()
    base = Path(data_dir)
    out_events = events_dir(replay_dir)
    out_prov = provenance_dir(replay_dir)
    out_events.mkdir(parents=True, exist_ok=True)
    out_prov.mkdir(parents=True, exist_ok=True)
    for path in discover_dataset_files(Path(source)):
        _load_one(path, base, out_events, out_prov, batch_size, summary)
    summary.seconds = time.monotonic() - started
    return summary


def _load_one(
    path: Path,
    data_dir: Path,
    out_events: Path,
    out_prov: Path,
    batch_size: int,
    summary: LoadSummary,
) -> None:
    """Stream one dataset file into its events/provenance Parquet pair.

    Each pair is written to ``<slug>.parquet.tmp`` and moved into place
    with :func:`os.replace` only after the file finished: a load killed
    mid-file leaves no truncated ``*.parquet`` behind to break DuckDB
    queries. Tmp files are removed again when the file fails.
    """
    rel = data_relative(path, data_dir)
    slug = slug_for_rel(rel)
    stats = WindowsReadStats()
    event_rows: list[dict[str, Any]] = []
    prov_rows: list[dict[str, Any]] = []
    file_events = 0
    file_has_in_band = False
    events_path = out_events / f"{slug}.parquet"
    prov_path = out_prov / f"{slug}.parquet"
    events_tmp = out_events / f"{slug}.parquet.tmp"
    prov_tmp = out_prov / f"{slug}.parquet.tmp"
    try:
        with (
            pq.ParquetWriter(events_tmp, EVENTS_SCHEMA) as event_writer,
            pq.ParquetWriter(prov_tmp, PROVENANCE_SCHEMA) as prov_writer,
        ):
            for event in iter_dataset_file(path, dataset_rel=rel, stats=stats):
                uid = event.metadata.uid or ""
                in_band = has_in_band_technique_id(event)
                event_rows.append(event_to_row(event))
                prov_rows.append(provenance_to_row(uid, rel, in_band))
                file_events += 1
                summary.events_total += 1
                summary.per_class[event.class_uid] = (
                    summary.per_class.get(event.class_uid, 0) + 1
                )
                if in_band:
                    summary.in_band_events += 1
                    file_has_in_band = True
                if len(event_rows) >= batch_size:
                    _write_rows(event_writer, EVENTS_SCHEMA, event_rows)
                    _write_rows(prov_writer, PROVENANCE_SCHEMA, prov_rows)
            if event_rows:
                _write_rows(event_writer, EVENTS_SCHEMA, event_rows)
                _write_rows(prov_writer, PROVENANCE_SCHEMA, prov_rows)
    except BaseException:
        for tmp in (events_tmp, prov_tmp):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    os.replace(events_tmp, events_path)
    os.replace(prov_tmp, prov_path)
    summary.files_loaded += 1
    if file_events == 0:
        summary.files_empty += 1
    if file_has_in_band:
        summary.in_band_files += 1
    for key, count in stats.unmapped.items():
        summary.unmapped[key] = summary.unmapped.get(key, 0) + count
    summary.unsupported += stats.unsupported


def format_summary(summary: LoadSummary, replay_dir: str | Path) -> str:
    """Render the load summary printed by ``corvus replay load``."""
    lines = [
        f"loaded {summary.files_loaded} files in {summary.seconds:.1f}s",
        f"store: {replay_dir}",
        f"files with zero mapped events: {summary.files_empty}",
    ]
    classes = ", ".join(
        f"{uid}: {summary.per_class[uid]}" for uid in sorted(summary.per_class)
    )
    lines.append(f"events: {summary.events_total} total ({classes})")
    unmapped_total = sum(summary.unmapped.values())
    lines.append(
        f"unmapped: {unmapped_total} records "
        f"in {len(summary.unmapped)} (channel, event id) buckets; "
        f"unsupported: {summary.unsupported} members"
    )
    lines.append(
        f"in-band technique ids: {summary.in_band_events} events "
        f"in {summary.in_band_files} files"
    )
    return "\n".join(lines)
