"""Read-only Wazuh adapter: indexer REST API -> OCSF.

Reads alerts from ``wazuh-alerts-4.x-*`` and archive context from
``wazuh-archives-4.x-*`` through :class:`ReadOnlyIndexerClient` and
maps hits with :mod:`corvus.normalize.wazuh`. Rule translation and
deployment stay unimplemented: they belong to the later rule
backtest and shadow-deployment milestone (``docs/architecture.md``
section 4, "Rule -> backtest -> Wazuh shadow deployment").

``stream_alerts`` pages with ``search_after`` on the stable sort
``[timestamp asc, _id asc]`` (the document ``_id`` is the unique last
key: the archive ``id`` field repeats across documents) inside one
fresh point in time per call. Each call re-reads an overlap window
(``overlap_seconds``, default 120 s) behind the persisted cursor and
drops only records whose uid is already in the cursor's seen set, so
late-indexed alerts are neither skipped nor duplicated. The cursor
lives in the ``checkpoints`` table (adapter ``"wazuh"``, stream
``"alerts"``) as the last time plus the ``(time, uid)`` pairs emitted
from the current overlap window, and survives restarts. Late alerts
older than the overlap window stay missed; that bound is documented,
not silent.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import psycopg

from corvus.adapters.siem import (
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
    SourceEntry,
    SourceInventory,
    ValidationResult,
    _category_for_source,
)
from corvus.adapters.wazuh.client import IndexerError, ReadOnlyIndexerClient
from corvus.normalize.wazuh import map_alert, map_archive
from corvus.settings import Settings
from corvus.state.checkpoints import load_checkpoint, save_checkpoint

__all__ = [
    "ADAPTER_NAME",
    "ALERTS_INDEX",
    "ARCHIVES_INDEX",
    "DEFAULT_OVERLAP_SECONDS",
    "STREAM_NAME",
    "WazuhAdapter",
]

#: Adapter/stream names used for the ``checkpoints`` table rows.
ADAPTER_NAME = "wazuh"
STREAM_NAME = "alerts"

#: Index patterns read by this adapter (never written).
ALERTS_INDEX = "wazuh-alerts-4.x-*"
ARCHIVES_INDEX = "wazuh-archives-4.x-*"

#: Overlap window re-read behind the cursor on every poll.
DEFAULT_OVERLAP_SECONDS = 120

#: Stable sort for every read: event time, then the document ``_id``.
#: The alerts ``id`` field is unique per manager, but the archive
#: ``id`` repeats across documents, so only ``_id`` (sortable per the
#: OpenSearch 2.19 docs) orders both indices without skipping rows.
_SORT = [
    {"timestamp": {"order": "asc"}},
    {"_id": {"order": "asc"}},
]

#: Extra hits fetched per page so the overlap re-read still fills a
#: full page of unseen events.
_OVERLAP_PAD = 100

#: Page requests per ``stream_alerts``/``query_events`` call at most.
_MAX_PAGES_PER_CALL = 10

#: Cap for the cursor seen set (``(time, uid)`` pairs). Pruning keeps
#: only pairs inside the current overlap window; the cap bounds the
#: in-memory and stored checkpoint when a cursor is carried without a
#: database, dropping the oldest pairs first.
_MAX_SEEN = 10_000

#: Point-in-time lifetime per call (fresh PIT per call, closed after).
_PIT_KEEP_ALIVE = "1m"

#: Rule surface milestone named by every rule-method error.
_RULE_MILESTONE = (
    "the rule backtest and shadow-deployment milestone "
    "(docs/architecture.md section 4: Rule -> backtest -> "
    "Wazuh shadow deployment)"
)


def _seen_pairs(raw: Any) -> list[tuple[int, str]]:
    """Return the valid ``(time_ms, uid)`` pairs from stored JSON."""
    pairs: list[tuple[int, str]] = []
    if not isinstance(raw, list):
        return pairs
    for entry in raw:
        if (
            isinstance(entry, list)
            and len(entry) == 2
            and isinstance(entry[0], int)
            and isinstance(entry[1], str)
            and entry[1]
        ):
            pairs.append((entry[0], entry[1]))
    return pairs


class WazuhAdapter:
    """Read-only :class:`SiemAdapter` over the Wazuh indexer."""

    def __init__(
        self,
        client: ReadOnlyIndexerClient,
        *,
        overlap_seconds: int = DEFAULT_OVERLAP_SECONDS,
        database_url: str | None = None,
    ) -> None:
        """Bind the adapter to one read-only indexer client.

        ``overlap_seconds`` is the late-index overlap window re-read
        behind the cursor on every poll. ``database_url`` enables
        checkpoint persistence in the ``checkpoints`` table.
        """
        if overlap_seconds < 0:
            raise ValueError(f"overlap_seconds must be >= 0, got {overlap_seconds}")
        self._client = client
        self._overlap_seconds = overlap_seconds
        self._database_url = database_url
        self.unmapped_counts: dict[tuple[str, str | None], int] = {}

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        database_url: str | None = None,
        overlap_seconds: int = DEFAULT_OVERLAP_SECONDS,
        transport: Any = None,
    ) -> WazuhAdapter:
        """Build the adapter from environment settings only.

        Requires ``WAZUH_INDEXER_URL`` (https), ``WAZUH_INDEXER_USER``
        and ``WAZUH_INDEXER_PASSWORD``; ``WAZUH_INDEXER_CA`` selects
        the CA bundle for the self-signed indexer certificate (the
        platform trust store otherwise). TLS verification is always
        on; there is no flag to disable it.
        """
        missing = [
            name
            for name, value in (
                ("WAZUH_INDEXER_URL", settings.wazuh_indexer_url),
                ("WAZUH_INDEXER_USER", settings.wazuh_indexer_user),
                ("WAZUH_INDEXER_PASSWORD", settings.wazuh_indexer_password),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"wazuh adapter needs {', '.join(missing)} from the environment"
            )
        assert settings.wazuh_indexer_url is not None
        assert settings.wazuh_indexer_user is not None
        assert settings.wazuh_indexer_password is not None
        client = ReadOnlyIndexerClient(
            settings.wazuh_indexer_url,
            settings.wazuh_indexer_user,
            settings.wazuh_indexer_password,
            ca_path=settings.wazuh_indexer_ca,
            transport=transport,
        )
        return cls(client, overlap_seconds=overlap_seconds, database_url=database_url)

    def _count_unmapped(self, key: tuple[str, str | None]) -> None:
        """Count one unmapped document per ``(decoder, rule id)``."""
        self.unmapped_counts[key] = self.unmapped_counts.get(key, 0) + 1

    def _load_cursor(self) -> Cursor | None:
        """Return the persisted cursor, or None when absent/unusable.

        Database errors raise instead of silently re-reading from the
        beginning (which would re-emit everything): only a missing row
        or an unusable shape falls back to a fresh cursor.
        """
        if self._database_url is None:
            return None
        try:
            stored = load_checkpoint(self._database_url, ADAPTER_NAME, STREAM_NAME)
        except psycopg.Error as exc:
            raise RuntimeError(
                f"wazuh checkpoint load failed for {ADAPTER_NAME}/{STREAM_NAME}: {exc}"
            ) from exc
        last_time = stored.get("last_time")
        last_uid = stored.get("last_uid")
        if not isinstance(last_time, int):
            return None
        if last_uid is not None and not isinstance(last_uid, str):
            return None
        seen = _seen_pairs(stored.get("seen"))
        window_start = last_time - self._overlap_seconds * 1000
        seen = [(time_ms, uid) for time_ms, uid in seen if time_ms >= window_start]
        return Cursor(
            last_time=last_time, last_uid=last_uid, seen=tuple(seen[-_MAX_SEEN:])
        )

    def _save_cursor(self, cursor: Cursor) -> None:
        """Persist the cursor (best effort; polls must not fail on it).

        Save failures are swallowed: the next poll re-reads from its
        in-memory cursor, and the checkpoint catches up on the next
        successful save.
        """
        if self._database_url is None:
            return
        try:
            save_checkpoint(
                self._database_url,
                ADAPTER_NAME,
                STREAM_NAME,
                {
                    "last_time": cursor.last_time,
                    "last_uid": cursor.last_uid,
                    "seen": [list(pair) for pair in cursor.seen],
                },
            )
        except Exception:
            pass

    def _search_pit_pages(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int,
        max_pages: int = _MAX_PAGES_PER_CALL,
    ) -> list[dict[str, Any]]:
        """Return raw hits in sort order from one fresh point in time."""
        pit_id = self._client.create_pit(index, _PIT_KEEP_ALIVE)
        try:
            hits: list[dict[str, Any]] = []
            search_after: list[Any] | None = None
            for _ in range(max_pages):
                body: dict[str, Any] = {"size": size, "query": query, "sort": _SORT}
                if search_after is not None:
                    body["search_after"] = search_after
                page = self._client.search_pit(pit_id, body)
                batch = page.get("hits", {}).get("hits", [])
                if not isinstance(batch, list) or not batch:
                    return hits
                hits.extend(batch)
                last = batch[-1]
                search_after = last.get("sort")
                if not isinstance(search_after, list) or not search_after:
                    return hits
                if len(batch) < size:
                    return hits
            return hits
        finally:
            self._client.delete_pit(pit_id)

    def stream_alerts(
        self,
        since: Cursor | None = None,
        page_size: int = DEFAULT_STREAM_PAGE_SIZE,
    ) -> tuple[list[OcsfEvent], Cursor]:
        """Return up to ``page_size`` unseen events and the cursor.

        Re-reads the overlap window behind the cursor and drops only
        records whose uid is already in the cursor's seen set, so
        late-indexed alerts are emitted exactly once and never
        skipped. A page cut can split one alert's finding and event
        across polls: the seen set makes the cut safe in both
        directions. The returned cursor carries the new last time plus
        the ``(time, uid)`` pairs emitted from its overlap window, and
        is persisted when a database is configured.
        """
        if page_size < 1 or page_size > MAX_STREAM_PAGE_SIZE:
            raise ValueError(
                f"page_size must be 1..{MAX_STREAM_PAGE_SIZE}, got {page_size}"
            )
        cursor = since or self._load_cursor() or Cursor()
        seen: set[str] = {uid for _, uid in cursor.seen}
        if cursor.last_time is not None:
            query: dict[str, Any] = {
                "range": {
                    "timestamp": {
                        "gte": cursor.last_time - self._overlap_seconds * 1000
                    }
                }
            }
        else:
            query = {"match_all": {}}
        hits = self._search_pit_pages(
            ALERTS_INDEX, query, size=min(page_size + _OVERLAP_PAD, 1000)
        )
        collected: list[OcsfEvent] = []
        emitted: list[tuple[int, str]] = []
        for hit in hits:
            if len(collected) >= page_size:
                break
            if not isinstance(hit, dict):
                continue
            try:
                finding, event, unmapped_key = map_alert(hit)
            except ValueError:
                self._count_unmapped(("unknown", None))
                continue
            if unmapped_key is not None:
                self._count_unmapped(unmapped_key)
            for record in (finding, event):
                if record is None:
                    continue
                uid = record.metadata.uid or ""
                if uid in seen:
                    continue
                collected.append(record)
                emitted.append((record.time, uid))
                seen.add(uid)
                if len(collected) >= page_size:
                    break
        if not collected:
            return collected, cursor
        times = [time_ms for time_ms, _ in emitted]
        if cursor.last_time is not None:
            times.append(cursor.last_time)
        new_last_time = max(times)
        window_start = new_last_time - self._overlap_seconds * 1000
        carried = [
            (time_ms, uid) for time_ms, uid in cursor.seen if time_ms >= window_start
        ]
        kept = [(time_ms, uid) for time_ms, uid in emitted if time_ms >= window_start]
        new_seen = (carried + kept)[-_MAX_SEEN:]
        new_cursor = Cursor(
            last_time=new_last_time,
            last_uid=collected[-1].metadata.uid,
            seen=tuple(new_seen),
        )
        self._save_cursor(new_cursor)
        return collected, new_cursor

    def _archive_query(
        self,
        entity: Entity | None,
        start: int | None,
        end: int | None,
    ) -> dict[str, Any]:
        """Build the archives bool query (entity AND time window)."""
        clauses: list[dict[str, Any]] = []
        if entity is not None:
            if entity.host is not None:
                clauses.append({"term": {"agent.name": entity.host}})
            if entity.user is not None:
                clauses.append(
                    {
                        "bool": {
                            "should": [
                                {"term": {"data.srcuser": entity.user}},
                                {"term": {"data.dstuser": entity.user}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                )
            if entity.ip is not None:
                clauses.append({"term": {"data.srcip": entity.ip}})
        if start is not None:
            clauses.append({"range": {"timestamp": {"gte": start}}})
        if end is not None:
            clauses.append({"range": {"timestamp": {"lte": end}}})
        if not clauses:
            return {"match_all": {}}
        return {"bool": {"filter": clauses}}

    def query_events(
        self,
        entity: Entity | None = None,
        start: int | None = None,
        end: int | None = None,
        classes: list[int] | None = None,
        limit: int = 200,
    ) -> list[OcsfEvent]:
        """Query archives by entity and time window, oldest first.

        ``host`` matches the Wazuh agent name, ``user`` the documented
        ``data.srcuser``/``data.dstuser`` fields, ``ip`` the documented
        ``data.srcip`` field. OCSF class filtering happens after
        mapping; archive documents no decoder maps are counted per
        ``(decoder, rule id)`` and skipped.
        """
        if limit < 1 or limit > MAX_QUERY_LIMIT:
            raise ValueError(f"limit must be 1..{MAX_QUERY_LIMIT}, got {limit}")
        if start is not None and end is not None and start > end:
            raise ValueError(f"start {start} is after end {end}")
        query = self._archive_query(entity, start, end)
        wanted = set(classes) if classes is not None else None
        matched: list[OcsfEvent] = []
        search_after: list[Any] | None = None
        pit_id = self._client.create_pit(ARCHIVES_INDEX, _PIT_KEEP_ALIVE)
        try:
            for _ in range(_MAX_PAGES_PER_CALL):
                if len(matched) >= limit:
                    break
                body: dict[str, Any] = {
                    "size": min(limit, 200),
                    "query": query,
                    "sort": _SORT,
                }
                if search_after is not None:
                    body["search_after"] = search_after
                page = self._client.search_pit(pit_id, body)
                batch = page.get("hits", {}).get("hits", [])
                if not isinstance(batch, list) or not batch:
                    break
                for hit in batch:
                    if len(matched) >= limit:
                        break
                    if not isinstance(hit, dict):
                        continue
                    try:
                        event, unmapped_key = map_archive(hit)
                    except ValueError:
                        self._count_unmapped(("unknown", None))
                        continue
                    if unmapped_key is not None:
                        self._count_unmapped(unmapped_key)
                        continue
                    assert event is not None
                    if wanted is not None and event.class_uid not in wanted:
                        continue
                    matched.append(event)
                last = batch[-1]
                search_after = last.get("sort")
                if not isinstance(search_after, list) or not search_after:
                    break
                if len(batch) < min(limit, 200):
                    break
        finally:
            self._client.delete_pit(pit_id)
        return matched

    def translate_rule(self, sigma: SigmaRule) -> NativeRule:
        """Not implemented: rule translation is a later milestone."""
        raise NotImplementedError(
            "WazuhAdapter.translate_rule is not implemented: Sigma rule "
            f"translation belongs to {_RULE_MILESTONE}."
        )

    def validate_rule(
        self, native: NativeRule, samples: list[OcsfEvent]
    ) -> ValidationResult:
        """Not implemented: rule backtesting is a later milestone."""
        raise NotImplementedError(
            "WazuhAdapter.validate_rule is not implemented: rule backtesting "
            f"belongs to {_RULE_MILESTONE}."
        )

    def deploy_rule(self, native: NativeRule, mode: DeployMode) -> Deployment:
        """Not implemented: shadow deployment is a later milestone."""
        raise NotImplementedError(
            "WazuhAdapter.deploy_rule is not implemented: Wazuh shadow "
            f"deployment belongs to {_RULE_MILESTONE}."
        )

    def rollback_rule(self, deployment: Deployment) -> None:
        """Not implemented: shadow deployment is a later milestone."""
        raise NotImplementedError(
            "WazuhAdapter.rollback_rule is not implemented: Wazuh shadow "
            f"deployment belongs to {_RULE_MILESTONE}."
        )

    def update_list(
        self,
        name: str,
        indicators: list[Indicator],
        ttl: timedelta | None = None,
    ) -> int:
        """Not implemented: CDB indicator lists are roadmap (rule 8)."""
        raise NotImplementedError(
            "WazuhAdapter.update_list is not implemented: CDB indicator "
            "lists are roadmap (AGENTS.md rule 8)."
        )

    def describe_sources(
        self, window: tuple[int, int] | None = None, sample_size: int = 20
    ) -> SourceInventory:
        """Aggregate decoder, agent, and time coverage from archives.

        Runs one aggregation over the archives index in the window
        (terms on ``decoder.name``, cardinality on ``agent.name``,
        counts and min/max ``timestamp``, plus up to ``sample_size``
        sample documents per decoder) and one cheap decoder listing
        over the alerts index. One entry per decoder carries the OCSF
        classes mapped from its samples, the host and event counts,
        and the first/last seen times. Class 2004 appears only for
        decoders that also have alerts. Archives hold every event
        (alerts are a small subset), so they are the inventory source
        of truth.
        """
        if window is not None:
            first, last = window
            if first > last:
                raise ValueError(f"window start {first} is after end {last}")
            query: dict[str, Any] = {
                "range": {"timestamp": {"gte": first, "lte": last}}
            }
        else:
            query = {"match_all": {}}
        if not 1 <= sample_size <= 100:
            raise ValueError(f"sample_size must be 1..100, got {sample_size}")
        archives_body = {
            "size": 0,
            "query": query,
            "aggs": {
                "by_decoder": {
                    "terms": {"field": "decoder.name", "size": 1000},
                    "aggs": {
                        "first_seen": {"min": {"field": "timestamp"}},
                        "last_seen": {"max": {"field": "timestamp"}},
                        "agents": {"cardinality": {"field": "agent.name"}},
                        "samples": {
                            "top_hits": {
                                "size": sample_size,
                                "sort": [{"timestamp": {"order": "asc"}}],
                                "_source": True,
                            }
                        },
                    },
                }
            },
        }
        alerts_body = {
            "size": 0,
            "query": query,
            "aggs": {"by_decoder": {"terms": {"field": "decoder.name", "size": 1000}}},
        }
        archives_parsed = self._client.search(ARCHIVES_INDEX, archives_body)
        alerts_parsed = self._client.search(ALERTS_INDEX, alerts_body)
        archive_buckets = (
            archives_parsed.get("aggregations", {})
            .get("by_decoder", {})
            .get("buckets", [])
        )
        alert_buckets = (
            alerts_parsed.get("aggregations", {})
            .get("by_decoder", {})
            .get("buckets", [])
        )
        if not isinstance(archive_buckets, list) or not isinstance(alert_buckets, list):
            raise IndexerError(
                "wazuh indexer describe_sources failed: unexpected response shape"
            )
        alert_decoders = {
            bucket.get("key") for bucket in alert_buckets if isinstance(bucket, dict)
        }
        entries: list[SourceEntry] = []
        for bucket in archive_buckets:
            if not isinstance(bucket, dict):
                continue
            decoder = bucket.get("key")
            if not isinstance(decoder, str) or not decoder:
                continue
            event_count = int(bucket.get("doc_count", 0) or 0)
            first_seen = bucket.get("first_seen", {}).get("value")
            last_seen = bucket.get("last_seen", {}).get("value")
            host_count = bucket.get("agents", {}).get("value")
            sample_hits = bucket.get("samples", {}).get("hits", {}).get("hits", [])
            if not isinstance(sample_hits, list):
                sample_hits = []
            classes: set[int] = set()
            sample_events: list[OcsfEvent] = []
            for sample in sample_hits[:sample_size]:
                if not isinstance(sample, dict):
                    continue
                try:
                    event, unmapped_key = map_archive(sample)
                except ValueError:
                    self._count_unmapped(("unknown", None))
                    continue
                if unmapped_key is not None:
                    self._count_unmapped(unmapped_key)
                    continue
                assert event is not None
                classes.add(event.class_uid)
                sample_events.append(event)
            if decoder in alert_decoders:
                classes.add(2004)
            if classes:
                category = _category_for_source(
                    "wazuh", decoder, sorted(classes), sample_events
                )
            else:
                category = "other"
            entries.append(
                SourceEntry(
                    source=f"wazuh:{decoder}",
                    category=category,
                    product="wazuh",
                    decoder=decoder,
                    classes=sorted(classes),
                    host_count=int(host_count or 0),
                    event_count=event_count,
                    first_seen=int(first_seen) if first_seen is not None else 0,
                    last_seen=int(last_seen) if last_seen is not None else 0,
                )
            )
        entries.sort(key=lambda entry: entry.source)
        return SourceInventory(sources=entries)


if TYPE_CHECKING:
    # Fails `make lint` if WazuhAdapter drifts from the Protocol
    # (mypy only checks corvus/, so tests cannot carry this assertion).
    _: type[SiemAdapter] = WazuhAdapter
