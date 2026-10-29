"""Evaluate compiled Sigma rules over the replay Parquet store.

One group at a time: stream the store's event files sequentially
(never holding the whole store in memory), keep the rows of the
group's OCSF slice, build one in-memory DuckDB table per group, and
run each rule's SQL against it. Each slice is therefore scanned once
per rule group. A rule whose SQL fails at runtime is counted as an
evaluation error and yields no findings, never aborting the run.

``peak_rss_mb`` (max resident set size of the process) and wall time
are reported alongside the matches so the detect report can quote
them.
"""

from __future__ import annotations

import json
import resource
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from corvus.detect.backend import FULLTEXT_COLUMN
from corvus.detect.mapping import GROUPS, GroupDef, extract_row
from corvus.detect.rules import CompiledRule

__all__ = [
    "EvaluateStats",
    "MatchedEvent",
    "evaluate",
    "peak_rss_mb",
]

#: Rows fetched from DuckDB per batch (bounds result buffering).
FETCH_SIZE = 5000


@dataclass
class MatchedEvent:
    """The stored fields of one matched event needed for a finding."""

    uid: str
    time: int
    class_uid: int
    activity_id: int
    host: str | None
    device: dict[str, Any] | None
    actor: dict[str, Any] | None
    process: dict[str, Any] | None
    file: dict[str, Any] | None
    src_endpoint: dict[str, Any] | None
    dst_endpoint: dict[str, Any] | None


@dataclass
class EvaluateStats:
    """Counts for one evaluate run (reported, never event content)."""

    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    rules_run: int = 0
    rules_errored: dict[str, str] = field(default_factory=dict)
    matches: int = 0
    events_scanned: int = 0
    events_matched: int = 0
    seconds: float = 0.0
    peak_rss_mb: float = 0.0


def peak_rss_mb() -> float:
    """Return the process max resident set size in MiB."""
    import sys

    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes, Linux kilobytes.
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024


def _event_files(replay_dir: str | Path) -> list[Path]:
    from corvus.adapters.replay.schema import events_dir

    directory = events_dir(replay_dir)
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.parquet"))


def _slice_mask(table: pa.Table, group: GroupDef) -> list[bool]:
    """Vectorized slice filter over the flat event columns."""
    import pyarrow.compute as pc

    classes = pc.is_in(
        table.column("class_uid"), value_set=pa.array(sorted(group.class_uids))
    )
    logs = pc.is_in(
        table.column("log_name"), value_set=pa.array(sorted(group.log_names))
    )
    mask = pc.and_(classes, logs)
    if group.activity_ids is not None:
        activities = pc.is_in(
            table.column("activity_id"),
            value_set=pa.array(sorted(group.activity_ids)),
        )
        mask = pc.and_(mask, activities)
    result = mask.to_pylist()
    return [bool(keep) for keep in result]


def _iter_group_rows(
    files: list[Path],
    group: GroupDef,
    *,
    need_fulltext: bool,
    raw_fallback: bool,
) -> tuple[list[dict[str, Any]], dict[str, MatchedEvent], int]:
    """Stream every store file, extracting this group's slice rows.

    Flat columns filter the slice first; ``event_json`` is read only
    for slice rows, so a group never holds non-slice records. Returns
    the DuckDB row dicts, the matched-event info keyed by uid (filled
    for every slice row; the caller keeps only matched uids), and the
    scanned row count.
    """
    rows: list[dict[str, Any]] = []
    infos: dict[str, MatchedEvent] = {}
    scanned = 0
    for path in files:
        flat = pq.read_table(
            path,
            columns=["class_uid", "activity_id", "log_name"],
        )
        scanned += flat.num_rows
        mask = _slice_mask(flat, group)
        if not any(mask):
            continue
        indices = pa.array(
            [index for index, keep in enumerate(mask) if keep], type=pa.int64()
        )
        detail = pq.read_table(
            path,
            columns=["uid", "time", "host", "event_json"],
        ).take(indices)
        for record in detail.to_pylist():
            try:
                event = json.loads(record["event_json"])
            except ValueError, TypeError:
                continue
            if not isinstance(event, dict):
                continue
            row = extract_row(
                event, group, need_fulltext=need_fulltext, raw_fallback=raw_fallback
            )
            row["uid"] = record["uid"]
            row["time"] = record["time"]
            rows.append(row)
            uid = record["uid"]
            class_uid = event.get("class_uid")
            activity_id = event.get("activity_id")
            if (
                uid is not None
                and uid not in infos
                and isinstance(class_uid, int)
                and isinstance(activity_id, int)
            ):
                infos[uid] = MatchedEvent(
                    uid=uid,
                    time=record["time"],
                    class_uid=class_uid,
                    activity_id=activity_id,
                    host=record["host"],
                    device=event.get("device"),
                    actor=event.get("actor"),
                    process=event.get("process"),
                    file=event.get("file"),
                    src_endpoint=event.get("src_endpoint"),
                    dst_endpoint=event.get("dst_endpoint"),
                )
    return rows, infos, scanned


def evaluate(
    replay_dir: str | Path,
    compiled: list[CompiledRule],
    *,
    raw_fallback: bool = True,
) -> tuple[dict[str, set[str]], dict[str, MatchedEvent], EvaluateStats]:
    """Run every compiled rule over the replay store.

    Returns ``(matches, infos, stats)``: per-rule matched event uid
    sets, per-uid event info for matched events, and run counts with
    wall time and peak RSS in MiB. ``raw_fallback=False`` keeps strict
    nulls (measurement only, for the old-vs-new match delta).
    """
    started = time.monotonic()
    stats = EvaluateStats()
    matches: dict[str, set[str]] = {}
    infos: dict[str, MatchedEvent] = {}
    files = _event_files(replay_dir)
    by_group: dict[str, list[CompiledRule]] = defaultdict(list)
    for rule in compiled:
        by_group[rule.group].append(rule)
    for group_name in sorted(by_group):
        group = GROUPS[group_name]
        rules = sorted(by_group[group_name], key=lambda item: item.rule_id)
        group_started = time.monotonic()
        need_fulltext = any(FULLTEXT_COLUMN in rule.sql for rule in rules)
        rows, group_infos, scanned = _iter_group_rows(
            files, group, need_fulltext=need_fulltext, raw_fallback=raw_fallback
        )
        stats.events_scanned += scanned
        group_matches = 0
        with duckdb.connect() as connection:
            _load_slice(connection, group, rows)
            for rule in rules:
                stats.rules_run += 1
                try:
                    uids = _run_rule(connection, rule)
                except Exception as exc:
                    stats.rules_errored[rule.rule_id] = (
                        f"{type(exc).__name__}: {str(exc)[:120]}"
                    )
                    continue
                matches[rule.rule_id] = uids
                group_matches += len(uids)
                for uid in uids:
                    if uid not in infos and uid in group_infos:
                        infos[uid] = group_infos[uid]
        stats.groups[group_name] = {
            "rules": len(rules),
            "rows": len(rows),
            "matches": group_matches,
            "seconds": round(time.monotonic() - group_started, 1),
        }
        stats.matches += group_matches
    stats.events_matched = len(infos)
    stats.seconds = time.monotonic() - started
    stats.peak_rss_mb = peak_rss_mb()
    return matches, infos, stats


def _load_slice(
    connection: duckdb.DuckDBPyConnection,
    group: GroupDef,
    rows: list[dict[str, Any]],
) -> None:
    """Build the ``slice`` view for one group's rows (empty slice OK)."""
    import pyarrow as pa

    columns = ["uid", "time", *sorted(group.fields)]
    if any(FULLTEXT_COLUMN in row for row in rows):
        columns.append(FULLTEXT_COLUMN)
    table = pa.table({name: [row.get(name) for row in rows] for name in columns})
    connection.register("src", table)
    connection.execute("CREATE OR REPLACE TABLE slice AS SELECT * FROM src")
    connection.unregister("src")


def _run_rule(connection: duckdb.DuckDBPyConnection, rule: CompiledRule) -> set[str]:
    """Run one rule's SQL, returning matched event uids."""
    cursor = connection.execute(f"SELECT uid FROM ({rule.sql})")
    names = [column[0] for column in cursor.description]
    uid_index = names.index("uid")
    found: set[str] = set()
    while True:
        batch = cursor.fetchmany(FETCH_SIZE)
        if not batch:
            return found
        for record in batch:
            uid = record[uid_index]
            if uid is not None:
                found.add(str(uid))
