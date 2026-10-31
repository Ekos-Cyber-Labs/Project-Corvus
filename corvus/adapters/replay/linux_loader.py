"""Load Wazuh Linux archive documents into a replay Parquet store.

:func:`load_linux_path` accepts ``ossec-archive-*.json.gz`` and
``*.json`` files (the uncompressed current-day file included) or a
directory, and normalizes every document through
:func:`corvus.normalize.wazuh.map_linux_doc` into per-file
``events/<slug>.parquet`` plus ``provenance/<slug>.parquet`` pairs
written atomically, following the Windows loader conventions.

Provenance keeps the data-relative path, the file SHA-256 and the
1-based line number (keyed by event uid), plus the dataset and the
in-band-technique flag. A ``manifest.json`` in the store records the
SHA-256 of every completed file: reruns skip completed files, and a
load killed mid-file leaves only ``*.tmp`` files behind, so loads
are resumable and idempotent (loading twice adds nothing).

Serial join: documents of one audit event share the kernel serial but
arrive as separate documents (SYSCALL plus EXECVE/CWD/PATH/PROCTITLE
companions, usually adjacent within a few dozen lines). Companions
are held in a bounded pending map (``serial_lag`` lines) and merged
into the SYSCALL document's ``full_log`` before mapping, so one
execution yields one event; companions whose SYSCALL never arrives
count as unmapped. Duplicates (auth.log/journald copies, companion
repeats) collapse on the dedupe key from
:func:`corvus.normalize.wazuh.linux_dedup_key` and count as
deduplicated.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from corvus.adapters.replay.schema import event_to_row, slug_for_rel
from corvus.normalize.technique_ids import has_in_band_technique_id
from corvus.normalize.wazuh import map_linux_doc

__all__ = [
    "LINUX_PROVENANCE_SCHEMA",
    "LinuxLoadSummary",
    "discover_linux_files",
    "format_linux_summary",
    "linux_events_dir",
    "linux_provenance_dir",
    "load_linux_path",
]

#: Rows buffered before one Parquet write (bounds loader memory).
LINUX_BATCH_SIZE = 5000

#: How many lines a serial group may lag behind the read head before
#: it flushes (same-serial documents sit within ~20 lines in the
#: lab archives; the bound keeps memory flat on huge files).
SERIAL_LAG = 64

#: Linux provenance columns: uid plus file SHA-256 and line number,
#: so any stored event traces back to its exact archive line.
LINUX_PROVENANCE_SCHEMA = pa.schema(
    [
        ("uid", pa.string()),
        ("file", pa.string()),
        ("line", pa.int64()),
        ("sha256", pa.string()),
        ("dataset", pa.string()),
        ("in_band_technique_id", pa.bool_()),
    ]
)


@dataclass
class LinuxLoadSummary:
    """Counts for one :func:`load_linux_path` run (printed by the CLI)."""

    files_loaded: int = 0
    files_skipped: int = 0
    lines_read: int = 0
    malformed: int = 0
    merged: int = 0
    events_total: int = 0
    per_class: dict[int, int] = field(default_factory=dict)
    unmapped: dict[tuple[str, str | None], int] = field(default_factory=dict)
    deduplicated: int = 0
    seconds: float = 0.0
    in_band_events: int = 0


def linux_events_dir(replay_dir: str | Path) -> Path:
    """Return the ``events/`` output directory under ``replay_dir``."""
    return Path(replay_dir) / "events"


def linux_provenance_dir(replay_dir: str | Path) -> Path:
    """Return the ``provenance/`` output directory under ``replay_dir``."""
    return Path(replay_dir) / "provenance"


def _manifest_path(replay_dir: str | Path) -> Path:
    return Path(replay_dir) / "manifest.json"


def _read_manifest(replay_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads(_manifest_path(replay_dir).read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _write_manifest(replay_dir: Path, manifest: dict[str, Any]) -> None:
    tmp = _manifest_path(replay_dir).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, _manifest_path(replay_dir))


def discover_linux_files(source: Path) -> list[Path]:
    """List Linux archive files under ``source`` (a file or dir), sorted.

    Accepts ``ossec-archive-*.json.gz`` and ``*.json`` (the
    uncompressed current-day file); anything else raises. A missing
    path raises instead of loading zero events.
    """
    if not source.exists():
        raise ValueError(f"linux archive path does not exist: {source}")
    if source.is_file():
        if source.suffix == ".gz" or source.suffix == ".json":
            return [source]
        raise ValueError(f"unsupported linux archive suffix for {source}")
    found = sorted(
        path
        for path in source.rglob("*")
        if path.is_file() and (path.suffix in (".json", ".gz"))
    )
    return found


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _open_lines(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def _dataset_for_rel(data_rel: str) -> str:
    return data_rel.split("/", 1)[0] if "/" in data_rel else data_rel


def _existing_uids(out_events: Path) -> set[str]:
    """Return event uids already in the store (empty when never loaded)."""
    uids: set[str] = set()
    if not out_events.is_dir():
        return uids
    for parquet in sorted(out_events.glob("*.parquet")):
        try:
            uids.update(
                pq.read_table(parquet, columns=["uid"]).column("uid").to_pylist()
            )
        except OSError, ValueError:
            continue
    return uids


def _is_companion(doc: dict[str, Any]) -> bool:
    """True for EXECVE/CWD/PATH/PROCTITLE standalone documents."""
    data = doc.get("data")
    audit = data.get("audit") if isinstance(data, dict) else None
    audit_type = audit.get("type") if isinstance(audit, dict) else None
    return audit_type in ("EXECVE", "CWD", "PATH", "PROCTITLE")


def _is_syscall(doc: dict[str, Any]) -> bool:
    data = doc.get("data")
    audit = data.get("audit") if isinstance(data, dict) else None
    audit_type = audit.get("type") if isinstance(audit, dict) else None
    return audit_type == "SYSCALL"


def _serial_of(doc: dict[str, Any]) -> str | None:
    data = doc.get("data")
    audit = data.get("audit") if isinstance(data, dict) else None
    serial = audit.get("id") if isinstance(audit, dict) else None
    return serial if isinstance(serial, str) and serial else None


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


def load_linux_path(
    source: str | Path,
    *,
    replay_dir: str | Path = "data/replay-linux",
    data_dir: str | Path = "data",
    batch_size: int = LINUX_BATCH_SIZE,
    serial_lag: int = SERIAL_LAG,
) -> LinuxLoadSummary:
    """Normalize Linux archives into Parquet under ``replay_dir``."""
    from corvus.adapters.replay.schema import EVENTS_SCHEMA

    started = time.monotonic()
    summary = LinuxLoadSummary()
    base = Path(data_dir)
    store = Path(replay_dir)
    out_events = linux_events_dir(store)
    out_prov = linux_provenance_dir(store)
    out_events.mkdir(parents=True, exist_ok=True)
    out_prov.mkdir(parents=True, exist_ok=True)
    manifest = _read_manifest(store)
    seen_uids = _existing_uids(out_events)
    seen_dedupes: set[str] = set()
    for entry in manifest.values():
        if isinstance(entry, dict) and isinstance(entry.get("dedupes"), list):
            seen_dedupes.update(entry["dedupes"])
    for path in discover_linux_files(Path(source)):
        try:
            rel = path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            raise ValueError(
                f"{path} is outside the dataset root {base}; provenance "
                "paths must stay data-relative"
            ) from None
        digest = _sha256_file(path)
        entry = manifest.get(rel)
        if isinstance(entry, dict) and entry.get("sha256") == digest:
            summary.files_skipped += 1
            continue
        slug = slug_for_rel(rel)
        file_stats: dict[str, Any] = {
            "sha256": digest,
            "dedupes": [],
            "unmapped": [],
        }
        stats = _load_one(
            path,
            rel,
            digest,
            slug,
            out_events,
            out_prov,
            EVENTS_SCHEMA,
            batch_size,
            serial_lag,
            summary,
            seen_uids,
            seen_dedupes,
            file_stats,
        )
        manifest[rel] = stats
        _write_manifest(store, manifest)
        summary.files_loaded += 1
    summary.seconds = time.monotonic() - started
    return summary


def _load_one(
    path: Path,
    rel: str,
    digest: str,
    slug: str,
    out_events: Path,
    out_prov: Path,
    events_schema: pa.Schema,
    batch_size: int,
    serial_lag: int,
    summary: LinuxLoadSummary,
    seen_uids: set[str],
    seen_dedupes: set[str],
    file_stats: dict[str, Any],
) -> dict[str, Any]:
    """Stream one archive file into its events/provenance Parquet pair."""
    event_rows: list[dict[str, Any]] = []
    prov_rows: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}
    file_mapped = 0
    file_unmapped: Counter[tuple[str, str | None]] = Counter()
    file_dedupes: set[str] = set()
    events_path = out_events / f"{slug}.parquet"
    prov_path = out_prov / f"{slug}.parquet"
    events_tmp = out_events / f"{slug}.parquet.tmp"
    prov_tmp = out_prov / f"{slug}.parquet.tmp"
    lineno = 0

    def emit(
        doc: dict[str, Any],
        line: int,
        event_writer: pq.ParquetWriter,
        prov_writer: pq.ParquetWriter,
    ) -> None:
        nonlocal file_mapped
        _finding, event, unmapped_key, dedupe = map_linux_doc(doc)
        if dedupe in seen_dedupes or (
            event is not None
            and event.metadata.uid is not None
            and event.metadata.uid in seen_uids
        ):
            summary.deduplicated += 1
            return
        seen_dedupes.add(dedupe)
        file_dedupes.add(dedupe)
        if event is None:
            summary.unmapped[unmapped_key or ("unknown", None)] = (
                summary.unmapped.get(unmapped_key or ("unknown", None), 0) + 1
            )
            file_unmapped[unmapped_key or ("unknown", None)] += 1
            return
        uid = event.metadata.uid or ""
        in_band = has_in_band_technique_id(event)
        event_rows.append(event_to_row(event))
        prov_rows.append(
            {
                "uid": uid,
                "file": rel,
                "line": line,
                "sha256": digest,
                "dataset": _dataset_for_rel(rel),
                "in_band_technique_id": in_band,
            }
        )
        seen_uids.add(uid)
        summary.events_total += 1
        file_mapped += 1
        summary.per_class[event.class_uid] = (
            summary.per_class.get(event.class_uid, 0) + 1
        )
        if in_band:
            summary.in_band_events += 1
        if len(event_rows) >= batch_size:
            _write_rows(event_writer, events_schema, event_rows)
            _write_rows(prov_writer, LINUX_PROVENANCE_SCHEMA, prov_rows)

    def flush(
        pos: int,
        event_writer: pq.ParquetWriter,
        prov_writer: pq.ParquetWriter,
    ) -> None:
        stale = [
            serial
            for serial, group in pending.items()
            if group["pos"] < pos - serial_lag
        ]
        for serial in stale:
            group = pending.pop(serial)
            syscall_doc = group["syscall"]
            if syscall_doc is None:
                # Companions without a SYSCALL: each counts as
                # unmapped (never emitted, so no dedupe keys).
                for _full, _line in group["blobs"]:
                    summary.unmapped[("auditd", None)] = (
                        summary.unmapped.get(("auditd", None), 0) + 1
                    )
                    file_unmapped[("auditd", None)] += 1
                continue
            merged = dict(syscall_doc)
            own = syscall_doc.get("full_log") or ""
            extra = "".join(
                full for full, _line in group["blobs"] if isinstance(full, str)
            )
            if extra and extra not in own:
                merged["full_log"] = own + "\x1d" + extra
                summary.merged += len(group["blobs"])
            emit(merged, group["line"], event_writer, prov_writer)

    try:
        with (
            pq.ParquetWriter(events_tmp, events_schema) as event_writer,
            pq.ParquetWriter(prov_tmp, LINUX_PROVENANCE_SCHEMA) as prov_writer,
        ):
            with _open_lines(path) as handle:
                for raw in handle:
                    lineno += 1
                    line = raw.strip()
                    if not line:
                        continue
                    summary.lines_read += 1
                    try:
                        doc = json.loads(line)
                    except ValueError:
                        summary.malformed += 1
                        continue
                    if not isinstance(doc, dict):
                        summary.malformed += 1
                        continue
                    if _is_syscall(doc):
                        serial = _serial_of(doc)
                        if serial is None:
                            emit(doc, lineno, event_writer, prov_writer)
                        else:
                            group = pending.setdefault(
                                serial,
                                {
                                    "pos": lineno,
                                    "syscall": None,
                                    "blobs": [],
                                    "line": lineno,
                                },
                            )
                            if group["syscall"] is not None:
                                # A duplicated serial: the first
                                # document wins, the repeat is
                                # deduplicated, never double-counted.
                                summary.deduplicated += 1
                            else:
                                group["syscall"] = doc
                                group["line"] = lineno
                    elif _is_companion(doc):
                        serial = _serial_of(doc)
                        if serial is None:
                            emit(doc, lineno, event_writer, prov_writer)
                        else:
                            group = pending.setdefault(
                                serial,
                                {
                                    "pos": lineno,
                                    "syscall": None,
                                    "blobs": [],
                                    "line": lineno,
                                },
                            )
                            full = doc.get("full_log")
                            group["blobs"].append((full, lineno))
                    else:
                        emit(doc, lineno, event_writer, prov_writer)
                    flush(lineno, event_writer, prov_writer)
            flush(lineno + serial_lag + 1, event_writer, prov_writer)
            if event_rows:
                _write_rows(event_writer, events_schema, event_rows)
                _write_rows(prov_writer, LINUX_PROVENANCE_SCHEMA, prov_rows)
    except BaseException:
        for tmp in (events_tmp, prov_tmp):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    os.replace(events_tmp, events_path)
    os.replace(prov_tmp, prov_path)
    file_stats["dedupes"] = sorted(file_dedupes)
    file_stats["lines"] = lineno
    file_stats["mapped"] = file_mapped
    file_stats["unmapped"] = sorted(
        ((decoder, rule, count) for (decoder, rule), count in file_unmapped.items()),
        key=lambda item: (str(item[0]), str(item[1])),
    )
    return file_stats


def format_linux_summary(summary: LinuxLoadSummary, replay_dir: str | Path) -> str:
    """Render the load summary printed by ``corvus replay load-linux``."""
    lines = [
        f"loaded {summary.files_loaded} files "
        f"({summary.files_skipped} skipped) in {summary.seconds:.1f}s",
        f"store: {replay_dir}",
        f"lines read: {summary.lines_read} "
        f"(malformed: {summary.malformed}, merged: {summary.merged}, "
        f"deduplicated: {summary.deduplicated})",
    ]
    classes = ", ".join(
        f"{uid}: {summary.per_class[uid]}" for uid in sorted(summary.per_class)
    )
    lines.append(f"events: {summary.events_total} total ({classes})")
    unmapped_total = sum(summary.unmapped.values())
    lines.append(
        f"unmapped: {unmapped_total} documents "
        f"in {len(summary.unmapped)} (decoder, rule id) buckets"
    )
    lines.append(f"in-band technique ids: {summary.in_band_events} events")
    return "\n".join(lines)
