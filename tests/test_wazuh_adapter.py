"""Tests for the read-only Wazuh adapter (HTTP-boundary fakes only).

``httpx2.MockTransport`` stands in for the indexer: no real OpenSearch
is needed, and no test here reaches the network or the filesystem
except the Postgres-backed restart test (guarded helpers from
``tests/conftest.py``) and the localhost TLS tests (a stub HTTPS
server on 127.0.0.1 with throwaway certificates, plus the
``openssl`` CLI at test time).
Secrets are fixed distinct strings so redaction is checkable.
"""

import json
import shutil
import socket
import ssl
import subprocess
import threading
from datetime import UTC
from pathlib import Path
from typing import Any

import httpx2
import pytest

from corvus.adapters.siem import Entity, Indicator, SiemAdapter
from corvus.adapters.wazuh import (
    ReadOnlyIndexerClient,
    WazuhAdapter,
)
from corvus.adapters.wazuh.client import IndexerError

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"

PASSWORD = "s3cret-indexer-pw"
USERNAME = "indexer-reader"
BASE_URL = "https://wazuh-indexer.test:9200"

ALERT_NAMES = ["sshd_failure", "sshd_success", "sudo"]


def _hit(name: str) -> dict[str, Any]:
    """Return one alerts-index hit with OpenSearch sort values."""
    doc = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    source = doc["_source"]
    from corvus.normalize.wazuh import parse_wazuh_time

    time_ms = parse_wazuh_time(source["timestamp"])
    return {
        "_index": doc["_index"],
        "_id": doc["_id"],
        "_source": source,
        "sort": [time_ms, doc["_id"]],
    }


def _archive_hit(name: str, doc_id: str, time_ms: int, agent: str) -> dict[str, Any]:
    """Return one archives-index hit for entity/time-window tests."""
    doc = json.loads((FIXTURES / "archive_sshd.json").read_text(encoding="utf-8"))
    source = dict(doc["_source"])
    source["id"] = doc_id
    source["agent"] = {"id": "001", "name": agent, "ip": "192.0.2.10"}
    return {
        "_index": "wazuh-archives-4.x-2024-05-02",
        "_id": f"mock-{doc_id}",
        "_source": source,
        "sort": [time_ms, f"mock-{doc_id}"],
    }


class FakeIndexer:
    """Canned OpenSearch over ``httpx2.MockTransport``.

    Serves alert hits and archive hits with real ``search_after``
    paging, records every request, and replays scripted statuses for
    the retry tests. Point-in-time open/search/close follow the
    OpenSearch 2.19 API shape.
    """

    def __init__(
        self,
        alerts: list[dict[str, Any]] | None = None,
        archives: list[dict[str, Any]] | None = None,
        aggs: dict[str, Any] | None = None,
        statuses: list[int] | None = None,
    ) -> None:
        self.alerts = alerts or []
        self.archives = archives or []
        self.aggs = aggs
        self.statuses = list(statuses or [])
        self.requests: list[httpx2.Request] = []
        self.bodies: list[Any] = []
        self.sleeps: list[float] = []
        self.pit_id = "test-pit-id"
        self.pit_indexes: dict[str, str] = {}
        self.pit_counter = 0
        self.transport = httpx2.MockTransport(self._handle)

    def client(self) -> ReadOnlyIndexerClient:
        """Build the read-only client over this fake indexer."""
        return ReadOnlyIndexerClient(
            BASE_URL,
            USERNAME,
            PASSWORD,
            max_retries=3,
            backoff_base_s=0.0,
            sleeper=self.sleeps.append,
            transport=self.transport,
        )

    def adapter(self, **kwargs: Any) -> WazuhAdapter:
        """Build the adapter over this fake indexer."""
        return WazuhAdapter(self.client(), **kwargs)

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        try:
            self.bodies.append(
                json.loads(request.content.decode("utf-8")) if request.content else None
            )
        except ValueError:
            self.bodies.append(None)
        if self.statuses:
            status = self.statuses.pop(0)
            if status != 200:
                return httpx2.Response(status, json={"error": "injected"})
        path = request.url.path
        body = self.bodies[-1] or {}
        if path.endswith("/_search/point_in_time"):
            self.pit_counter += 1
            pit_id = f"{self.pit_id}-{self.pit_counter}"
            self.pit_indexes[pit_id] = path.split("/_search/point_in_time")[0]
            return httpx2.Response(200, json={"pit_id": pit_id})
        if path == "/_search/point_in_time":
            assert request.method == "DELETE"
            return httpx2.Response(200, json={"succeeded": True, "num_freed": 1})
        if path == "/_search":
            pit_id = body.get("pit", {}).get("id")
            assert pit_id in self.pit_indexes, f"unknown pit {pit_id!r}"
            index = self.pit_indexes[pit_id]
            hits = self.archives if "wazuh-archives" in index else self.alerts
            return httpx2.Response(200, json=self._page(hits, body))
        if path.endswith("/_search"):
            if self.aggs is not None and body.get("size") == 0:
                key = "archives" if "wazuh-archives" in path else "alerts"
                return httpx2.Response(200, json=self.aggs[key])
            if "wazuh-archives" in path:
                return httpx2.Response(200, json=self._page(self.archives, body))
            return httpx2.Response(200, json=self._page(self.alerts, body))
        raise AssertionError(f"unexpected request {request.method} {path}")

    def _page(self, hits: list[dict[str, Any]], body: dict[str, Any]) -> dict[str, Any]:
        """Filter like the indexer, then slice by ``search_after``/``size``."""
        size = body.get("size", 10)
        after = body.get("search_after")
        ordered = sorted(hits, key=lambda hit: (hit["sort"][0], hit["sort"][1]))
        ordered = [hit for hit in ordered if self._matches(hit, body.get("query", {}))]
        if after is not None:
            ordered = [
                hit
                for hit in ordered
                if (hit["sort"][0], hit["sort"][1]) > (after[0], after[1])
            ]
        batch = ordered[:size]
        return {"hits": {"total": {"value": len(hits)}, "hits": batch}}

    @staticmethod
    def _value(hit: dict[str, Any], field: str) -> Any:
        """Read a dotted field from the hit source (``data.*`` aware)."""
        source = hit["_source"]
        if "." in field:
            head, _, rest = field.partition(".")
            if head == "data":
                node: Any = source.get("data", {})
            else:
                node = source.get(head, {})
            for part in rest.split("."):
                if not isinstance(node, dict):
                    return None
                node = node.get(part)
            return node
        return source.get(field)

    def _matches(self, hit: dict[str, Any], query: dict[str, Any]) -> bool:
        """Apply the adapter's bool/term/range query shape to one hit."""
        if not query or "match_all" in query:
            return True
        clauses = query.get("bool", {}).get("filter", [])
        for clause in clauses:
            if "term" in clause:
                [[field, want]] = list(clause["term"].items())
                if self._value(hit, field) != want:
                    return False
            elif "range" in clause:
                [[field, bounds]] = list(clause["range"].items())
                if field == "timestamp":
                    got = hit["sort"][0]
                else:
                    got = self._value(hit, field)
                if "gte" in bounds and got < bounds["gte"]:
                    return False
                if "lte" in bounds and got > bounds["lte"]:
                    return False
            elif "bool" in clause:
                should = clause["bool"].get("should", [])
                minimum = clause["bool"].get("minimum_should_match", 1)
                matched = sum(
                    1
                    for option in should
                    if self._matches(hit, {"bool": {"filter": [option]}})
                )
                if matched < minimum:
                    return False
            else:
                raise AssertionError(f"fake indexer cannot apply {clause!r}")
        return True

    def pit_requests(self) -> list[httpx2.Request]:
        """Return the PIT open/search/close requests in order."""
        return [
            request
            for request in self.requests
            if request.url.path.endswith("point_in_time")
            or request.url.path == "/_search"
        ]


def test_adapter_satisfies_protocol() -> None:
    fake = FakeIndexer()
    adapter: SiemAdapter = fake.adapter()
    assert isinstance(adapter, SiemAdapter)


def test_stream_alerts_uses_stable_sort_and_search_after() -> None:
    fake = FakeIndexer(alerts=[_hit(name) for name in ALERT_NAMES])
    adapter = fake.adapter()
    page, cursor = adapter.stream_alerts(page_size=2)
    assert [event.metadata.uid for event in page] == [
        "1714651200.10001",
        "1714651200.10001#event",
    ]
    assert (cursor.last_time, cursor.last_uid) == (
        page[-1].time,
        "1714651200.10001#event",
    )
    searches = [req for req in fake.requests if req.url.path == "/_search"]
    assert len(searches) == 1  # first page filled from one request
    first_body = json.loads(searches[0].content.decode("utf-8"))
    assert first_body["sort"] == [
        {"timestamp": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]
    assert "search_after" not in first_body
    # A second poll resumes after the cursor through the overlap
    # window and returns only the unseen suffix.
    page2, cursor2 = adapter.stream_alerts(since=cursor, page_size=10)
    assert [event.metadata.uid for event in page2] == [
        "1714651260.10002",
        "1714651260.10002#event",
        "1714651320.10003",
        "1714651320.10003#event",
    ]
    assert cursor2.last_uid == "1714651320.10003#event"
    second_search = [req for req in fake.requests if req.url.path == "/_search"][-1]
    second_body = json.loads(second_search.content.decode("utf-8"))
    assert second_body["query"] == {
        "range": {"timestamp": {"gte": cursor.last_time - 120_000}}
    }


def test_stream_alerts_pages_through_search_after() -> None:
    import copy

    base = _hit("sshd_failure")
    many: list[dict[str, Any]] = []
    for seq in range(105):
        hit = copy.deepcopy(base)
        doc_id = f"1714651200.{20000 + seq}"
        hit["_id"] = f"alert-doc-{seq:04d}"
        hit["_source"]["id"] = doc_id
        hit["sort"] = [1714651200048 + seq, hit["_id"]]
        many.append(hit)
    fake = FakeIndexer(alerts=many)
    adapter = fake.adapter()
    page, cursor = adapter.stream_alerts(page_size=2)
    assert len(page) == 2
    searches = [req for req in fake.requests if req.url.path == "/_search"]
    assert len(searches) == 2  # 102 hits, then the remaining 3
    bodies = [json.loads(req.content.decode("utf-8")) for req in searches]
    assert bodies[0].get("search_after") is None
    assert bodies[1]["search_after"] == many[101]["sort"]
    assert bodies[1]["sort"] == bodies[0]["sort"]
    assert bodies[1]["pit"]["id"] == bodies[0]["pit"]["id"]
    assert cursor.last_uid == page[-1].metadata.uid


def test_stream_alerts_manages_point_in_time() -> None:
    fake = FakeIndexer(alerts=[_hit("sshd_failure")])
    adapter = fake.adapter()
    adapter.stream_alerts()
    kinds = [(req.method, req.url.path) for req in fake.pit_requests()]
    assert kinds[0] == ("POST", "/wazuh-alerts-4.x-*/_search/point_in_time")
    assert kinds[1] == ("POST", "/_search")
    assert kinds[-1] == ("DELETE", "/_search/point_in_time")
    search_body = json.loads(fake.requests[1].content.decode("utf-8"))
    assert search_body["pit"]["id"] in fake.pit_indexes


def test_stream_alerts_rejects_bad_page_size() -> None:
    adapter = FakeIndexer().adapter()
    with pytest.raises(ValueError, match="page_size"):
        adapter.stream_alerts(page_size=0)
    with pytest.raises(ValueError, match="page_size"):
        adapter.stream_alerts(page_size=1001)


def test_query_events_filters_and_orders_oldest_first() -> None:
    archives = [
        _archive_hit("a", "1714651200.20001", 1714651200250, "web01"),
        _archive_hit("b", "1714651260.20002", 1714651260250, "db01"),
    ]
    fake = FakeIndexer(archives=archives)
    adapter = fake.adapter()
    events = adapter.query_events(Entity(host="web01"))
    assert [event.metadata.uid for event in events] == ["mock-1714651200.20001"]
    assert all(event.class_uid == 3002 for event in events)
    body = json.loads(
        [req for req in fake.requests if req.url.path == "/_search"][-1].content.decode(
            "utf-8"
        )
    )
    assert {"term": {"agent.name": "web01"}} in body["query"]["bool"]["filter"]
    assert body["sort"] == [
        {"timestamp": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]


def test_query_events_user_matches_srcuser_or_dstuser() -> None:
    archives = [_archive_hit("a", "1714651200.20001", 1714651200250, "web01")]
    fake = FakeIndexer(archives=archives)
    adapter = fake.adapter()
    assert len(adapter.query_events(Entity(user="deploy"))) == 1
    body = json.loads(
        [req for req in fake.requests if req.url.path == "/_search"][-1].content.decode(
            "utf-8"
        )
    )
    user_clause = [
        clause for clause in body["query"]["bool"]["filter"] if "bool" in clause
    ][0]
    should = user_clause["bool"]["should"]
    assert {"term": {"data.srcuser": "deploy"}} in should
    assert {"term": {"data.dstuser": "deploy"}} in should


def test_query_events_rejects_bad_limits_and_windows() -> None:
    adapter = FakeIndexer().adapter()
    with pytest.raises(ValueError, match="limit"):
        adapter.query_events(limit=0)
    with pytest.raises(ValueError, match="limit"):
        adapter.query_events(limit=201)
    with pytest.raises(ValueError, match="start"):
        adapter.query_events(start=2, end=1)


def _archives_sample(name: str, doc_uid: str, time_ms: int) -> dict[str, Any]:
    """Return one archives top-hits sample with a document ``_id``."""
    import copy

    hit = copy.deepcopy(_hit(name))
    hit["_id"] = doc_uid
    hit["_index"] = "wazuh-archives-4.x-2024-05-02"
    hit["_source"].pop("rule", None)
    hit["sort"] = [time_ms, doc_uid]
    return hit


def test_describe_sources_reads_archives_and_alert_decoders() -> None:
    auditd_samples = [
        _archives_sample("auditd_syscall", "audit-doc-1", 1714651380500),
        _archives_sample("auditd_syscall", "audit-doc-2", 1714651381500),
        _archives_sample("auditd_cwd", "audit-doc-3", 1714651382500),
    ]
    aggs = {
        "archives": {
            "aggregations": {
                "by_decoder": {
                    "buckets": [
                        {
                            "key": "auditd",
                            "doc_count": 77566,
                            "first_seen": {"value": 1714651380500.0},
                            "last_seen": {"value": 1714651382500.0},
                            "agents": {"value": 3},
                            "samples": {"hits": {"hits": auditd_samples}},
                        },
                        {
                            "key": "syscheck_integrity_changed",
                            "doc_count": 12,
                            "first_seen": {"value": 1714651440000.0},
                            "last_seen": {"value": 1714651440000.0},
                            "agents": {"value": 1},
                            "samples": {
                                "hits": {
                                    "hits": [
                                        _archives_sample(
                                            "syscheck_integrity_changed",
                                            "syscheck-doc-1",
                                            1714651440000,
                                        )
                                    ]
                                }
                            },
                        },
                    ]
                }
            }
        },
        "alerts": {
            "aggregations": {
                "by_decoder": {"buckets": [{"key": "auditd", "doc_count": 44}]}
            }
        },
    }
    fake = FakeIndexer(aggs=aggs)
    adapter = fake.adapter()
    inventory = adapter.describe_sources((1714651200000, 1714651600000))
    archives_reqs = [
        req for req in fake.requests if req.url.path == "/wazuh-archives-4.x-*/_search"
    ]
    alerts_reqs = [
        req for req in fake.requests if req.url.path == "/wazuh-alerts-4.x-*/_search"
    ]
    assert len(archives_reqs) == 1 and len(alerts_reqs) == 1
    archives_body = json.loads(archives_reqs[0].content.decode("utf-8"))
    by_decoder = archives_body["aggs"]["by_decoder"]
    assert by_decoder["terms"] == {"field": "decoder.name", "size": 1000}
    assert "by_group" not in by_decoder["aggs"]
    assert "rule.groups" not in json.dumps(archives_body)
    assert by_decoder["aggs"]["agents"] == {"cardinality": {"field": "agent.name"}}
    assert by_decoder["aggs"]["samples"]["top_hits"]["size"] == 20
    assert "first_seen" in by_decoder["aggs"] and "last_seen" in by_decoder["aggs"]
    alerts_body = json.loads(alerts_reqs[0].content.decode("utf-8"))
    assert alerts_body["size"] == 0
    assert set(alerts_body["aggs"]) == {"by_decoder"}
    assert "top_hits" not in json.dumps(alerts_body)
    by_source = {entry.source: entry for entry in inventory.sources}
    assert set(by_source) == {"wazuh:auditd", "wazuh:syscheck_integrity_changed"}
    auditd = by_source["wazuh:auditd"]
    assert auditd.category == "endpoint process"
    assert sorted(auditd.classes) == [1007, 2004]
    assert auditd.event_count == 77566 and auditd.host_count == 3
    assert auditd.first_seen == 1714651380500 and auditd.last_seen == 1714651382500
    syscheck = by_source["wazuh:syscheck_integrity_changed"]
    assert syscheck.classes == [1001]
    assert 2004 not in syscheck.classes
    assert syscheck.event_count == 12 and syscheck.first_seen == 1714651440000
    assert adapter.unmapped_counts.get(("auditd", None)) == 1


def test_describe_sources_rejects_bad_sample_size() -> None:
    adapter = FakeIndexer().adapter()
    with pytest.raises(ValueError, match="sample_size"):
        adapter.describe_sources(sample_size=0)
    with pytest.raises(ValueError, match="sample_size"):
        adapter.describe_sources(sample_size=101)


def test_rule_surface_is_not_implemented() -> None:
    from corvus.adapters.siem import Deployment, NativeRule, SigmaRule

    adapter = FakeIndexer().adapter()
    sigma = SigmaRule(title="x", yaml="title: x")
    native = NativeRule(rule_id=100001, xml="<group></group>")
    deployment = Deployment(
        deployment_id="wazuh-100001-shadow-1", rule_id=100001, mode="shadow"
    )
    with pytest.raises(NotImplementedError, match="shadow-deployment"):
        adapter.translate_rule(sigma)
    with pytest.raises(NotImplementedError, match="shadow-deployment"):
        adapter.validate_rule(native, [])
    with pytest.raises(NotImplementedError, match="shadow-deployment"):
        adapter.deploy_rule(native, "shadow")
    with pytest.raises(NotImplementedError, match="shadow-deployment"):
        adapter.rollback_rule(deployment)
    with pytest.raises(NotImplementedError, match="roadmap"):
        adapter.update_list(
            "blocked-ips", [Indicator(kind="ip", value="198.51.100.23")]
        )


def test_client_refuses_non_read_endpoints_before_sending() -> None:
    fake = FakeIndexer(alerts=[_hit("sshd_failure")])
    client = fake.client()
    sent_before = len(fake.requests)
    for method, path, operation in [
        ("PUT", "/wazuh-alerts-4.x-2024-05-02/_doc/1", "search"),
        ("POST", "/_bulk", "search"),
        ("GET", "/wazuh-other-*/_search", "search"),
        ("POST", "/wazuh-alerts-4.x-2024-05-02/_delete_by_query", "search"),
        ("POST", "/wazuh-alerts-4.x-2024-05-02/_search", "pit_delete"),
        # Combined indices and escapes pass fnmatch but must be refused.
        ("GET", "/wazuh-alerts-4.x-*,.other/_search", "search"),
        ("GET", "/wazuh-alerts-4.x-*,-x/_search", "search"),
        ("GET", "/wazuh-alerts-4.x-%2Cwazuh-other/_search", "search"),
        ("GET", "/wazuh-alerts-4.x-*+wazuh-other/_search", "search"),
        ("GET", "/wazuh-states-4.x-*/_search", "search"),
        ("GET", "/wazuh-states-*/_search", "search"),
        ("POST", "/wazuh-alerts-4.x-*,.other/_search/point_in_time", "pit_create"),
    ]:
        with pytest.raises(ValueError, match="read-only"):
            client._send(
                method,
                path,
                operation=operation,
                label="probe",
                body={},  # type: ignore[arg-type]
            )
    assert len(fake.requests) == sent_before


def test_client_requires_https_and_existing_ca() -> None:
    with pytest.raises(ValueError, match="https"):
        ReadOnlyIndexerClient("http://wazuh-indexer.test:9200", USERNAME, PASSWORD)
    with pytest.raises(FileNotFoundError, match="CA bundle"):
        ReadOnlyIndexerClient(
            BASE_URL, USERNAME, PASSWORD, ca_path="/nonexistent/ca.pem"
        )


def test_secrets_never_appear_in_errors_or_reprs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeIndexer(alerts=[_hit("sshd_failure")], statuses=[500, 500, 500, 500])
    client = fake.client()
    with pytest.raises(IndexerError) as excinfo:
        client.search("wazuh-alerts-4.x-*", {"query": {"match_all": {}}})
    assert PASSWORD not in str(excinfo.value)
    assert USERNAME not in str(excinfo.value)
    assert PASSWORD not in repr(client)
    assert PASSWORD not in caplog.text
    with pytest.raises(ValueError, match="read-only"):
        try:
            client._send("POST", "/_bulk", operation="search", label="probe", body={})
        except ValueError as exc:
            assert PASSWORD not in str(exc)
            raise


def test_client_retries_only_on_429_and_5xx() -> None:
    fake = FakeIndexer(alerts=[_hit("sshd_failure")], statuses=[500, 503, 200])
    client = fake.client()
    parsed = client.search("wazuh-alerts-4.x-*", {"query": {"match_all": {}}})
    assert parsed["hits"]["total"]["value"] == 1
    assert len(fake.sleeps) == 2  # backoff with jitter between the three attempts
    searches = [req for req in fake.requests if req.url.path.endswith("/_search")]
    assert len(searches) == 3

    fake = FakeIndexer(statuses=[400])
    with pytest.raises(IndexerError):
        fake.client().search("wazuh-alerts-4.x-*", {"query": {"match_all": {}}})
    assert len(fake.sleeps) == 0

    def raising(_: float) -> None:
        raise AssertionError("must not sleep on 400")

    fake = FakeIndexer(statuses=[400])
    client = ReadOnlyIndexerClient(
        BASE_URL, USERNAME, PASSWORD, sleeper=raising, transport=fake.transport
    )
    with pytest.raises(IndexerError):
        client.search("wazuh-alerts-4.x-*", {"query": {"match_all": {}}})


def test_from_settings_reads_environment_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from corvus.settings import Settings

    monkeypatch.setenv("DATABASE_URL", "postgresql://127.0.0.1:55432/corvus")
    monkeypatch.setenv("GLIMMER_BASE_URL", "http://glimmer-host:8001/v1")
    monkeypatch.setenv("WAZUH_INDEXER_URL", BASE_URL)
    monkeypatch.setenv("WAZUH_INDEXER_USER", USERNAME)
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", PASSWORD)
    monkeypatch.delenv("WAZUH_INDEXER_CA", raising=False)
    adapter = WazuhAdapter.from_settings(Settings())  # type: ignore[call-arg]
    assert repr(adapter._client).count(PASSWORD) == 0
    monkeypatch.delenv("WAZUH_INDEXER_PASSWORD")
    with pytest.raises(ValueError, match="WAZUH_INDEXER_PASSWORD"):
        WazuhAdapter.from_settings(Settings())  # type: ignore[call-arg]
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", PASSWORD)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "http://plain.test:9200")
    with pytest.raises(ValueError, match="https"):
        WazuhAdapter.from_settings(Settings())  # type: ignore[call-arg]


def test_stream_cursor_survives_restart_in_postgres() -> None:
    from corvus.state.migrate import migrate
    from tests.conftest import (
        _create_database,
        _drop_database,
        _test_database_urls,
    )

    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        first = FakeIndexer(alerts=[_hit("sshd_failure")])
        adapter = first.adapter(database_url=test_url)
        page, cursor = adapter.stream_alerts()
        assert len(page) == 2
        # A fresh adapter on the same database resumes behind the cursor:
        # the overlap re-read drops the already-seen alert.
        second = FakeIndexer(alerts=[_hit(name) for name in ALERT_NAMES])
        restarted = second.adapter(database_url=test_url)
        resumed, cursor2 = restarted.stream_alerts()
        assert [event.metadata.uid for event in resumed] == [
            "1714651260.10002",
            "1714651260.10002#event",
            "1714651320.10003",
            "1714651320.10003#event",
        ]
        assert cursor2.last_uid == "1714651320.10003#event"
        assert cursor.last_uid == "1714651200.10001#event"
    finally:
        _drop_database(admin_url, name)


def test_stream_counts_unmapped_without_dropping_findings() -> None:
    import json as jsonlib

    doc = jsonlib.loads((FIXTURES / "unknown_decoder.json").read_text(encoding="utf-8"))
    source = doc["_source"]
    from corvus.normalize.wazuh import parse_wazuh_time

    hit = {
        "_index": doc["_index"],
        "_id": doc["_id"],
        "_source": source,
        "sort": [parse_wazuh_time(source["timestamp"]), source["id"]],
    }
    fake = FakeIndexer(alerts=[hit])
    adapter = fake.adapter()
    page, _ = adapter.stream_alerts()
    assert len(page) == 1 and page[0].class_uid == 2004
    assert adapter.unmapped_counts == {("nginx-access", "100002"): 1}


def _alert_hit_at(alert_id: str, time_ms: int, name: str = "sshd_failure") -> dict:
    """Return one alerts-index hit with an explicit time and alert id."""
    import copy
    from datetime import datetime

    hit = copy.deepcopy(_hit(name))
    hit["_id"] = f"doc-{alert_id}"
    source = hit["_source"]
    source["id"] = alert_id
    moment = datetime.fromtimestamp(time_ms / 1000, tz=UTC)
    stamp = f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{time_ms % 1000:03d}+0000"
    source["timestamp"] = stamp
    source["@timestamp"] = stamp
    hit["sort"] = [time_ms, hit["_id"]]
    return hit


def test_stream_alerts_emits_late_indexed_alert_exactly_once() -> None:
    t0, t90, t100 = 1714651200000, 1714651290000, 1714651300000
    fake = FakeIndexer(
        alerts=[
            _alert_hit_at("1714651200.30001", t0),
            _alert_hit_at("1714651300.30002", t100),
        ]
    )
    adapter = fake.adapter()
    page, cursor = adapter.stream_alerts()
    assert [event.metadata.uid for event in page] == [
        "1714651200.30001",
        "1714651200.30001#event",
        "1714651300.30002",
        "1714651300.30002#event",
    ]
    # An alert indexed late, older than the cursor, is emitted once.
    fake.alerts.append(_alert_hit_at("1714651290.30003", t90))
    page2, cursor2 = adapter.stream_alerts(since=cursor)
    assert [event.metadata.uid for event in page2] == [
        "1714651290.30003",
        "1714651290.30003#event",
    ]
    assert cursor2.last_time == t100
    # A third poll re-reads the window and emits nothing new.
    page3, cursor3 = adapter.stream_alerts(since=cursor2)
    assert page3 == []
    assert cursor3 == cursor2


def test_stream_page_cut_mid_alert_is_safe() -> None:
    fake = FakeIndexer(alerts=[_hit("sshd_failure")])
    adapter = fake.adapter()
    page, cursor = adapter.stream_alerts(page_size=1)
    assert [event.metadata.uid for event in page] == ["1714651200.10001"]
    page2, cursor2 = adapter.stream_alerts(since=cursor)
    assert [event.metadata.uid for event in page2] == ["1714651200.10001#event"]
    page3, cursor3 = adapter.stream_alerts(since=cursor2)
    assert page3 == []
    assert cursor3 == cursor2


def test_load_cursor_database_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import psycopg

    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise psycopg.OperationalError("connection refused")

    monkeypatch.setattr("corvus.adapters.wazuh.adapter.load_checkpoint", _boom)
    adapter = FakeIndexer().adapter(database_url="postgresql://127.0.0.1:1/corvus")
    with pytest.raises(RuntimeError, match="checkpoint load failed"):
        adapter.stream_alerts()


def test_archives_repeated_ids_return_every_document_once() -> None:
    import copy

    time_ms = 1714651560250
    docs: list[dict[str, Any]] = []
    for seq in range(300):
        hit = copy.deepcopy(_hit("archive_sshd"))
        hit["_index"] = "wazuh-archives-4.x-2024-05-02"
        hit["_id"] = f"archive-doc-{seq:04d}"
        hit["_source"]["id"] = "1714651200.20001"
        if seq % 3 == 2:
            hit["_source"]["decoder"] = {"name": "auditd", "parent": "auditd"}
            hit["_source"]["data"] = {
                "audit": {"type": "CWD", "id": "1325", "cwd": "/home/deploy"}
            }
        hit["sort"] = [time_ms, hit["_id"]]
        docs.append(hit)
    fake = FakeIndexer(archives=docs)
    adapter = fake.adapter()
    events = adapter.query_events(limit=200)
    assert len(events) == 200
    uids = [event.metadata.uid for event in events]
    assert len(set(uids)) == 200
    assert uids == sorted(uids)
    assert all(uid.startswith("archive-doc-") for uid in uids)
    searches = [req for req in fake.requests if req.url.path == "/_search"]
    assert len(searches) >= 2
    assert searches[1] and "search_after" in json.loads(
        searches[1].content.decode("utf-8")
    )
    assert adapter.unmapped_counts.get(("auditd", None), 0) >= 1


TLS = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl CLI is missing"
)


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _make_ca(workdir: Path, name: str) -> tuple[Path, Path]:
    """Create a stock-like self-signed CA with no Key Usage extension."""
    key = workdir / f"{name}.key"
    crt = workdir / f"{name}.pem"
    _openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key),
        "-out",
        str(crt),
        "-days",
        "2",
        "-nodes",
        "-subj",
        f"/CN={name}",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        cwd=workdir,
    )
    return key, crt


def _issue_cert(
    workdir: Path, ca_key: Path, ca_crt: Path, name: str, san: str
) -> tuple[Path, Path]:
    """Issue a server certificate with the given subjectAltName."""
    key = workdir / f"{name}.key"
    csr = workdir / f"{name}.csr"
    crt = workdir / f"{name}.pem"
    ext = workdir / f"{name}.ext"
    ext.write_text(f"subjectAltName={san}\n", encoding="utf-8")
    _openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key),
        "-out",
        str(csr),
        "-nodes",
        "-subj",
        f"/CN={name}",
        cwd=workdir,
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(crt),
        "-days",
        "2",
        "-extfile",
        str(ext),
        cwd=workdir,
    )
    return key, crt


class _TlsStubIndexer:
    """Minimal stub HTTPS server speaking just enough OpenSearch."""

    def __init__(self, certfile: str, keyfile: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        self._context = context
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(16)
        self._socket.settimeout(0.5)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> _TlsStubIndexer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with self._context.wrap_socket(conn, server_side=True) as tls:
                    self._handle(tls)
            except ssl.SSLError, OSError, ValueError:
                pass

    def _handle(self, tls: ssl.SSLSocket) -> None:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = tls.recv(4096)
            if not chunk:
                return
            request += chunk
        head, _, rest = request.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        length = 0
        for line in lines[1:]:
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
        body = rest
        while len(body) < length:
            chunk = tls.recv(4096)
            if not chunk:
                break
            body += chunk
        path = target.split("?", 1)[0]
        if method == "POST" and path.endswith("/_search/point_in_time"):
            payload: dict[str, Any] = {"pit_id": "tls-pit"}
        elif method == "DELETE" and path == "/_search/point_in_time":
            payload = {"succeeded": True}
        elif path == "/_search":
            payload = {"hits": {"hits": [], "total": {"value": 0}}}
        else:
            payload = {"error": "not found"}
        raw = json.dumps(payload).encode("utf-8")
        tls.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(raw)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + raw
        )


@TLS
def test_tls_allows_stock_ca_without_strict_extensions(tmp_path: Path) -> None:
    ca_key, ca_crt = _make_ca(tmp_path, "test-ca")
    text = subprocess.run(
        ["openssl", "x509", "-in", str(ca_crt), "-text", "-noout"],
        capture_output=True,
        check=True,
        text=True,
        cwd=tmp_path,
    ).stdout
    assert "Key Usage" not in text
    assert "Authority Key Identifier" not in text
    _, srv_crt = _issue_cert(tmp_path, ca_key, ca_crt, "srv", "IP:127.0.0.1")
    server = _TlsStubIndexer(str(srv_crt), str(tmp_path / "srv.key")).start()
    try:
        client = ReadOnlyIndexerClient(
            f"https://127.0.0.1:{server.port}",
            USERNAME,
            PASSWORD,
            ca_path=str(ca_crt),
        )
        assert client.create_pit("wazuh-alerts-4.x-*") == "tls-pit"
        page = client.search_pit("tls-pit", {"query": {"match_all": {}}})
        assert page["hits"]["hits"] == []
        client.delete_pit("tls-pit")
    finally:
        server.stop()


@TLS
def test_tls_strict_flag_rejects_extensionless_ca(tmp_path: Path) -> None:
    ca_key, ca_crt = _make_ca(tmp_path, "test-ca")
    _, srv_crt = _issue_cert(tmp_path, ca_key, ca_crt, "srv", "IP:127.0.0.1")
    server = _TlsStubIndexer(str(srv_crt), str(tmp_path / "srv.key")).start()
    try:
        strict = ssl.create_default_context(cafile=str(ca_crt))
        strict.verify_flags |= ssl.VERIFY_X509_STRICT
        raw = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        try:
            with pytest.raises(ssl.SSLError):
                strict.wrap_socket(raw, server_hostname="127.0.0.1")
        finally:
            raw.close()
    finally:
        server.stop()


@TLS
def test_tls_rejects_unknown_ca_and_hostname_mismatch(tmp_path: Path) -> None:
    ca_key, ca_crt = _make_ca(tmp_path, "test-ca")
    _, other_crt = _make_ca(tmp_path, "other-ca")
    _, srv_crt = _issue_cert(tmp_path, ca_key, ca_crt, "srv", "IP:127.0.0.1")
    _, bad_crt = _issue_cert(tmp_path, ca_key, ca_crt, "bad", "DNS:example.com")
    good = _TlsStubIndexer(str(srv_crt), str(tmp_path / "srv.key")).start()
    bad = _TlsStubIndexer(str(bad_crt), str(tmp_path / "bad.key")).start()
    try:
        unknown = ReadOnlyIndexerClient(
            f"https://127.0.0.1:{good.port}",
            USERNAME,
            PASSWORD,
            ca_path=str(other_crt),
        )
        with pytest.raises(IndexerError):
            unknown.create_pit("wazuh-alerts-4.x-*")
        mismatched = ReadOnlyIndexerClient(
            f"https://127.0.0.1:{bad.port}",
            USERNAME,
            PASSWORD,
            ca_path=str(ca_crt),
        )
        with pytest.raises(IndexerError):
            mismatched.create_pit("wazuh-alerts-4.x-*")
    finally:
        good.stop()
        bad.stop()
