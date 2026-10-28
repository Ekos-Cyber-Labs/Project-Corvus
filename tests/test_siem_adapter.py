"""Behavior suite for the SiemAdapter protocol: FakeAdapter and ReplayAdapter.

Every behavior test runs against both implementations loaded from the
same fixture events, so the replay adapter honors the contract exactly
as the fake does. Fake-only tests cover the in-memory recording API;
replay-only tests cover the read-only rule surface.
"""

from datetime import timedelta
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from pydantic import ValidationError

from corvus.adapters.replay.adapter import ReplayAdapter
from corvus.adapters.replay.schema import EVENTS_SCHEMA, event_to_row, events_dir
from corvus.adapters.siem import (
    Cursor,
    Deployment,
    Entity,
    FakeAdapter,
    Indicator,
    NativeRule,
    SiemAdapter,
    SigmaRule,
    SourceInventory,
)
from corvus.normalize.ocsf import Authentication, OcsfEvent
from tests.fixtures.siem_events import (
    BASE_TIME_MS,
    MINUTE_MS,
    make_siem_fixture_events,
)

#: Fixture uids in ingestion order (wazuh-2 and wazuh-2b share a timestamp).
ALL_UIDS = [
    "wazuh-1",
    "wazuh-2",
    "wazuh-2b",
    "wazuh-3",
    "wazuh-4",
    "wazuh-5",
    "wazuh-6",
]


def _uids(events: list[OcsfEvent]) -> list[str | None]:
    return [event.metadata.uid for event in events]


def _write_replay_store(path: Path, events: list[OcsfEvent]) -> ReplayAdapter:
    """Persist fixture events as one replay events file; return the adapter."""
    directory = events_dir(path)
    directory.mkdir(parents=True, exist_ok=True)
    rows = [event_to_row(event) for event in events]
    table = pa.table(
        {
            name: pa.array(
                [row.get(name) for row in rows],
                type=EVENTS_SCHEMA.field(name).type,
            )
            for name in EVENTS_SCHEMA.names
        }
    )
    pq.write_table(table, directory / "fixture.parquet")
    return ReplayAdapter(path)


@pytest.fixture(params=["fake", "replay"])
def adapter(request: pytest.FixtureRequest, tmp_path: Path) -> SiemAdapter:
    """One behavior-suite adapter per implementation, same fixture events."""
    events = make_siem_fixture_events()
    if request.param == "fake":
        return FakeAdapter(events)
    return _write_replay_store(tmp_path / "replay", events)


def test_both_adapters_satisfy_protocol_statically_and_at_runtime(
    tmp_path: Path,
) -> None:
    fake: SiemAdapter = FakeAdapter(make_siem_fixture_events())
    assert isinstance(fake, SiemAdapter)
    replay: SiemAdapter = _write_replay_store(
        tmp_path / "replay", make_siem_fixture_events()
    )
    assert isinstance(replay, SiemAdapter)
    for instance in (fake, replay):
        for method in (
            "stream_alerts",
            "query_events",
            "translate_rule",
            "validate_rule",
            "deploy_rule",
            "rollback_rule",
            "update_list",
            "describe_sources",
        ):
            assert callable(getattr(instance, method))


def test_entity_rejects_fields_that_canonicalize_to_nothing() -> None:
    for kwargs in (
        {"host": "-"},
        {"host": "N/A"},
        {"host": "192.0.2.10"},
        {"user": "-"},
        {"user": "unknown"},
        {"ip": "not-an-ip"},
        {"ip": "-"},
        {},
        {"host": None, "user": None, "ip": None},
    ):
        with pytest.raises(ValidationError):
            Entity(**kwargs)


def test_entity_netbios_and_upn_spellings_do_not_match(
    adapter: SiemAdapter,
) -> None:
    assert Entity(user="EXAMPLE\\jdoe").user == "example\\jdoe"
    assert Entity(user="jdoe@example.com").user == "example.com\\jdoe"
    assert _uids(adapter.query_events(Entity(user="EXAMPLE\\jdoe"))) == [
        "wazuh-1",
        "wazuh-2",
        "wazuh-2b",
        "wazuh-3",
        "wazuh-4",
        "wazuh-6",
    ]
    assert adapter.query_events(Entity(user="jdoe@example.com")) == []


def test_query_events_filters_by_entity(adapter: SiemAdapter) -> None:
    assert _uids(adapter.query_events(Entity(host="web01"))) == [
        "wazuh-1",
        "wazuh-2",
        "wazuh-2b",
        "wazuh-3",
        "wazuh-4",
        "wazuh-6",
    ]
    # Canonicalization applies to the filter: FQDN and case still match.
    assert len(adapter.query_events(Entity(host="WEB01.EXAMPLE.COM"))) == 6
    assert _uids(adapter.query_events(Entity(host="db01"))) == ["wazuh-5"]
    assert _uids(adapter.query_events(Entity(user="example\\svc-backup"))) == [
        "wazuh-5"
    ]
    # Attacker IP matches via the endpoint address, not the device address.
    assert _uids(adapter.query_events(Entity(ip="198.51.100.23"))) == [
        "wazuh-1",
        "wazuh-2",
        "wazuh-2b",
    ]
    # AND across fields: jdoe never acted on db01.
    assert adapter.query_events(Entity(host="db01", user="example\\jdoe")) == []


def test_query_events_filters_by_time_window_inclusively(
    adapter: SiemAdapter,
) -> None:
    start = BASE_TIME_MS + MINUTE_MS
    end = BASE_TIME_MS + 3 * MINUTE_MS
    assert _uids(adapter.query_events(start=start, end=end)) == [
        "wazuh-2",
        "wazuh-2b",
        "wazuh-3",
        "wazuh-4",
    ]
    assert _uids(adapter.query_events(start=BASE_TIME_MS, end=BASE_TIME_MS)) == [
        "wazuh-1"
    ]


def test_query_events_rejects_start_after_end(adapter: SiemAdapter) -> None:
    with pytest.raises(ValueError, match="start"):
        adapter.query_events(start=BASE_TIME_MS + MINUTE_MS, end=BASE_TIME_MS)


def test_query_events_filters_by_class_and_respects_limit(
    adapter: SiemAdapter,
) -> None:
    assert _uids(adapter.query_events(classes=[4001])) == ["wazuh-4"]
    assert _uids(adapter.query_events(classes=[3002, 2004])) == [
        "wazuh-1",
        "wazuh-2",
        "wazuh-2b",
        "wazuh-6",
    ]
    page = adapter.query_events(limit=2)
    assert _uids(page) == ["wazuh-1", "wazuh-2"]
    with pytest.raises(ValueError, match="limit"):
        adapter.query_events(limit=0)
    with pytest.raises(ValueError, match="limit"):
        adapter.query_events(limit=201)


def test_stream_alerts_resumes_from_cursor_without_duplicates(
    adapter: SiemAdapter,
) -> None:
    page, cursor = adapter.stream_alerts()
    assert _uids(page) == ALL_UIDS
    resumed, cursor2 = adapter.stream_alerts(since=cursor)
    assert resumed == []
    assert cursor2 == cursor
    # Mid-stream cursor returns only the unseen suffix.
    mid = Cursor(last_time=BASE_TIME_MS + MINUTE_MS, last_uid="wazuh-2")
    suffix, _ = adapter.stream_alerts(since=mid)
    assert _uids(suffix) == ["wazuh-2b", "wazuh-3", "wazuh-4", "wazuh-5", "wazuh-6"]


def test_stream_alerts_pages_whole_fixture_in_pairs(
    adapter: SiemAdapter,
) -> None:
    seen: list[str | None] = []
    since: Cursor | None = None
    pages = 0
    while True:
        page, since = adapter.stream_alerts(since=since, page_size=2)
        if not page:
            break
        pages += 1
        assert len(page) <= 2
        seen.extend(_uids(page))
    # The shared-timestamp pair (wazuh-2, wazuh-2b) spans a page boundary.
    assert seen == ALL_UIDS
    assert pages == 4
    assert len(set(seen)) == len(seen)
    with pytest.raises(ValueError, match="page_size"):
        adapter.stream_alerts(page_size=0)
    with pytest.raises(ValueError, match="page_size"):
        adapter.stream_alerts(page_size=1001)


def test_fake_adapter_rejects_events_without_uid() -> None:
    orphan = Authentication(
        time=BASE_TIME_MS,
        metadata={
            "product": {"name": "wazuh", "vendor_name": "Wazuh"},
            "log_name": "Security",
        },
    )
    with pytest.raises(ValueError, match="metadata.uid"):
        FakeAdapter([orphan])
    with pytest.raises(ValueError, match="metadata.uid"):
        FakeAdapter([*make_siem_fixture_events(), orphan])


def test_describe_sources_groups_by_telemetry_source(
    adapter: SiemAdapter,
) -> None:
    inventory = adapter.describe_sources()
    assert isinstance(inventory, SourceInventory)
    by_source = {entry.source: entry for entry in inventory.sources}
    assert set(by_source) == {
        "wazuh:Security",
        "wazuh:Microsoft-Windows-Sysmon/Operational",
        "wazuh:suricata",
        "wazuh:syscheck",
        "wazuh:wazuh-manager",
    }
    expected = {
        "wazuh:Security": ("authentication", [3002], 3),
        "wazuh:Microsoft-Windows-Sysmon/Operational": (
            "endpoint process",
            [1007],
            1,
        ),
        "wazuh:suricata": ("network", [4001], 1),
        "wazuh:syscheck": ("endpoint process", [1001], 1),
        "wazuh:wazuh-manager": ("other", [2004], 1),
    }
    for source, (category, classes, count) in expected.items():
        entry = by_source[source]
        assert entry.category == category
        assert entry.classes == classes
        assert entry.event_count == count
        assert entry.product == "wazuh"
    # The unmapped Detection Finding source falls back to the class, which
    # is "other": findings never claim EDR telemetry on their own.
    assert by_source["wazuh:wazuh-manager"].category == "other"
    assert all(entry.category != "EDR" for entry in inventory.sources)
    # A window over the shared timestamp sees only the Security source.
    windowed = adapter.describe_sources(
        (BASE_TIME_MS + MINUTE_MS, BASE_TIME_MS + MINUTE_MS)
    )
    assert [e.source for e in windowed.sources] == ["wazuh:Security"]
    assert windowed.sources[0].event_count == 2


def test_fake_adapter_records_rule_calls() -> None:
    adapter = FakeAdapter(make_siem_fixture_events())
    sigma = SigmaRule(title="Suspicious encoded PowerShell", yaml="title: x")
    native = adapter.translate_rule(sigma)
    assert isinstance(native, NativeRule)
    assert 100000 <= native.rule_id <= 120000
    assert adapter.translate_calls == [sigma]
    samples = adapter.query_events(classes=[1007])
    result = adapter.validate_rule(native, samples)
    assert result.valid and result.errors == []
    assert adapter.validate_calls == [(native, samples)]
    deployment = adapter.deploy_rule(native, "shadow")
    assert isinstance(deployment, Deployment)
    assert deployment.rule_id == native.rule_id
    assert deployment.mode == "shadow"
    assert adapter.deploy_calls == [(native, "shadow")]
    adapter.rollback_rule(deployment)
    assert adapter.rollback_calls == [deployment]
    staged = adapter.update_list(
        "blocked-ips",
        [Indicator(kind="ip", value="198.51.100.23")],
        timedelta(hours=24),
    )
    assert staged == 1
    name, indicators, ttl = adapter.update_list_calls[0]
    assert (name, indicators, ttl) == (
        "blocked-ips",
        [Indicator(kind="ip", value="198.51.100.23")],
        timedelta(hours=24),
    )


def test_replay_adapter_rule_surface_is_read_only(tmp_path: Path) -> None:
    adapter = _write_replay_store(tmp_path / "replay", make_siem_fixture_events())
    sigma = SigmaRule(title="Suspicious encoded PowerShell", yaml="title: x")
    native = NativeRule(rule_id=100001, xml="<group></group>")
    deployment = Deployment(
        deployment_id="replay-100001-shadow-1", rule_id=100001, mode="shadow"
    )
    with pytest.raises(NotImplementedError, match="read-only"):
        adapter.translate_rule(sigma)
    with pytest.raises(NotImplementedError, match="read-only"):
        adapter.validate_rule(native, [])
    with pytest.raises(NotImplementedError, match="read-only"):
        adapter.deploy_rule(native, "shadow")
    with pytest.raises(NotImplementedError, match="read-only"):
        adapter.rollback_rule(deployment)
    with pytest.raises(NotImplementedError, match="roadmap"):
        adapter.update_list(
            "blocked-ips", [Indicator(kind="ip", value="198.51.100.23")]
        )
