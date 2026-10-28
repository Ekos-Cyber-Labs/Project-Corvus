"""Replay adapter: the :class:`SiemAdapter` contract over replay Parquet.

Events are read with DuckDB from the ``events/*.parquet`` files written
by :mod:`corvus.adapters.replay.loader`; every value from the caller
(entity fields, times, classes, limits) travels as a bound parameter,
never formatted into SQL text. Until replay alert generation exists,
:func:`stream_alerts` returns raw events in ``(time, uid)`` order from
the cursor. Rule methods stay ``NotImplementedError``: Sigma matching in
DuckDB must be case-insensitive (``ILIKE``), like Sigma itself.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb
from pydantic import TypeAdapter

from corvus.adapters.replay.schema import events_dir
from corvus.adapters.siem import (
    _CLASS_CATEGORY,
    _SOURCE_CATEGORY,
    DEFAULT_STREAM_PAGE_SIZE,
    MAX_QUERY_LIMIT,
    MAX_STREAM_PAGE_SIZE,
    Cursor,
    Deployment,
    DeployMode,
    Entity,
    Indicator,
    NativeRule,
    OcsfEvent,
    SiemAdapter,
    SigmaRule,
    SourceCategory,
    SourceEntry,
    SourceInventory,
    ValidationResult,
)

__all__ = ["ReplayAdapter"]

#: Rehydrates one stored ``event_json`` back into the OCSF union.
_EVENT_ADAPTER = TypeAdapter(OcsfEvent)


class ReplayAdapter:
    """Read-only :class:`SiemAdapter` over a replay Parquet store."""

    def __init__(self, replay_dir: str | Path = "data/replay") -> None:
        self._replay_dir = Path(replay_dir)

    def _event_files(self) -> list[str]:
        """Return the sorted event Parquet paths (empty when never loaded)."""
        directory = events_dir(self._replay_dir)
        if not directory.is_dir():
            return []
        return sorted(str(path) for path in directory.glob("*.parquet"))

    def _query(self, sql: str, params: list[Any]) -> list[tuple[Any, ...]]:
        """Run one DuckDB query over the event files with bound parameters."""
        files = self._event_files()
        if not files:
            return []
        with duckdb.connect() as connection:
            return connection.execute(
                sql.replace("REPLAY_EVENTS", "read_parquet(?)"),
                [files, *params],
            ).fetchall()

    def stream_alerts(
        self,
        since: Cursor | None = None,
        page_size: int = DEFAULT_STREAM_PAGE_SIZE,
    ) -> tuple[list[OcsfEvent], Cursor]:
        """Return up to ``page_size`` events after ``since`` in time order."""
        if page_size < 1 or page_size > MAX_STREAM_PAGE_SIZE:
            raise ValueError(
                f"page_size must be 1..{MAX_STREAM_PAGE_SIZE}, got {page_size}"
            )
        params: list[Any] = []
        where = ""
        if since is not None and since.last_time is not None:
            where = "WHERE (time > ? OR (time = ? AND uid > ?))"
            params.extend([since.last_time, since.last_time, since.last_uid or ""])
        rows = self._query(
            f"SELECT event_json FROM REPLAY_EVENTS {where} ORDER BY time, uid LIMIT ?",
            [*params, page_size],
        )
        page = [_EVENT_ADAPTER.validate_json(json_text) for (json_text,) in rows]
        if page:
            last = page[-1]
            cursor = Cursor(last_time=last.time, last_uid=last.metadata.uid)
        else:
            cursor = since if since is not None else Cursor()
        return page, cursor

    def query_events(
        self,
        entity: Entity | None = None,
        start: int | None = None,
        end: int | None = None,
        classes: list[int] | None = None,
        limit: int = 200,
    ) -> list[OcsfEvent]:
        """Filter by entity (AND), inclusive time window, classes, cap."""
        if limit < 1 or limit > MAX_QUERY_LIMIT:
            raise ValueError(f"limit must be 1..{MAX_QUERY_LIMIT}, got {limit}")
        if start is not None and end is not None and start > end:
            raise ValueError(f"start {start} is after end {end}")
        clauses: list[str] = []
        params: list[Any] = []
        if entity is not None:
            if entity.host is not None:
                clauses.append("host = ?")
                params.append(entity.host)
            if entity.user is not None:
                clauses.append("user = ?")
                params.append(entity.user)
            if entity.ip is not None:
                clauses.append("(ip = ? OR src_ip = ? OR dst_ip = ?)")
                params.extend([entity.ip, entity.ip, entity.ip])
        if start is not None:
            clauses.append("time >= ?")
            params.append(start)
        if end is not None:
            clauses.append("time <= ?")
            params.append(end)
        if classes is not None:
            clauses.append(f"class_uid IN ({', '.join('?' for _ in classes)})")
            params.extend(classes)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            f"SELECT event_json FROM REPLAY_EVENTS {where} ORDER BY time, uid LIMIT ?",
            [*params, limit],
        )
        return [_EVENT_ADAPTER.validate_json(json_text) for (json_text,) in rows]

    def translate_rule(self, sigma: SigmaRule) -> NativeRule:
        """Not implemented: replay is read-only until alert generation lands."""
        raise NotImplementedError(
            "ReplayAdapter.translate_rule is not implemented: the replay "
            "store is read-only until alert generation exists (Sigma "
            "matching in DuckDB must be case-insensitive, ILIKE)."
        )

    def validate_rule(
        self, native: NativeRule, samples: list[OcsfEvent]
    ) -> ValidationResult:
        """Not implemented: replay is read-only until alert generation lands."""
        raise NotImplementedError(
            "ReplayAdapter.validate_rule is not implemented: the replay "
            "store is read-only until alert generation exists (Sigma "
            "matching in DuckDB must be case-insensitive, ILIKE)."
        )

    def deploy_rule(self, native: NativeRule, mode: DeployMode) -> Deployment:
        """Not implemented: replay is read-only until alert generation lands."""
        raise NotImplementedError(
            "ReplayAdapter.deploy_rule is not implemented: the replay "
            "store is read-only until alert generation exists (Sigma "
            "matching in DuckDB must be case-insensitive, ILIKE)."
        )

    def rollback_rule(self, deployment: Deployment) -> None:
        """Not implemented: replay is read-only until alert generation lands."""
        raise NotImplementedError(
            "ReplayAdapter.rollback_rule is not implemented: the replay "
            "store is read-only until alert generation exists."
        )

    def update_list(
        self,
        name: str,
        indicators: list[Indicator],
        ttl: timedelta | None = None,
    ) -> int:
        """Not implemented: CDB indicator lists are roadmap (rule 8)."""
        raise NotImplementedError(
            "ReplayAdapter.update_list is not implemented: CDB indicator "
            "lists are roadmap (AGENTS.md rule 8)."
        )

    def describe_sources(
        self, window: tuple[int, int] | None = None
    ) -> SourceInventory:
        """Group stored events by product/log source within ``window``."""
        clauses: list[str] = []
        params: list[Any] = []
        if window is not None:
            first, last = window
            if first > last:
                raise ValueError(f"window start {first} is after end {last}")
            clauses += ["time >= ?", "time <= ?"]
            params += [first, last]
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            "SELECT product, log_name, class_uid, host, "
            "COUNT(*), MIN(time), MAX(time) FROM REPLAY_EVENTS "
            f"{where} GROUP BY product, log_name, class_uid, host",
            params,
        )
        grouped: dict[tuple[str, str], list[tuple[Any, ...]]] = {}
        for row in rows:
            grouped.setdefault((str(row[0]), str(row[1] or "")), []).append(row)
        entries = []
        for (product, log_name), group in sorted(grouped.items()):
            counts: dict[int, int] = {}
            hosts: set[str] = set()
            total = 0
            first_seen = 0
            last_seen = 0
            for _, _, class_uid, host, count, seen_first, seen_last in group:
                counts[int(class_uid)] = counts.get(int(class_uid), 0) + int(count)
                if host is not None:
                    hosts.add(str(host))
                total += int(count)
                seen_first, seen_last = int(seen_first), int(seen_last)
                first_seen = (
                    seen_first if not first_seen else min(first_seen, seen_first)
                )
                last_seen = max(last_seen, seen_last)
            classes = sorted(counts)
            entries.append(
                SourceEntry(
                    source=f"{product}:{log_name}" if log_name else product,
                    category=_category_for(product, log_name, counts),
                    product=product,
                    decoder=log_name or None,
                    classes=classes,
                    host_count=len(hosts),
                    event_count=total,
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )
        return SourceInventory(sources=entries)


def _category_for(
    product: str, log_name: str, counts: dict[int, int]
) -> SourceCategory:
    """Pick the inventory category from the source map, else the classes."""
    known = _SOURCE_CATEGORY.get((product, log_name))
    if known is not None:
        return known
    top = min(counts, key=lambda uid: (-counts[uid], uid))
    return _CLASS_CATEGORY.get(top, "endpoint process")


if TYPE_CHECKING:
    # Fails `make lint` if ReplayAdapter drifts from the Protocol.
    _: type[SiemAdapter] = ReplayAdapter
