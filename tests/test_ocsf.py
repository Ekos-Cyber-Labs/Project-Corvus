"""Tests for the pinned OCSF models in corvus/normalize/ocsf.py."""

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from corvus.normalize.ocsf import (
    MIN_TIME_MS,
    OCSF_SCHEMA_VERSION,
    Authentication,
    DetectionFinding,
    FileSystemActivity,
    NetworkActivity,
    OcsfEvent,
    Process,
    ProcessActivity,
    ScheduledJobActivity,
)

SAMPLE_TIME = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
SAMPLE_MS = 1793102400000

EVENT_ADAPTER: TypeAdapter[OcsfEvent] = TypeAdapter(OcsfEvent)


def _metadata() -> dict[str, object]:
    return {
        "product": {"name": "wazuh", "vendor_name": "Wazuh"},
        "log_name": "wazuh-alerts-*",
    }


def _user(name: str, domain: str | None = None) -> dict[str, object]:
    user: dict[str, object] = {"name": name}
    if domain is not None:
        user["domain"] = domain
    return {"user": user}


def test_schema_version_is_pinned_from_one_constant() -> None:
    event = Authentication(time=SAMPLE_TIME, metadata=_metadata())
    assert event.metadata.version == OCSF_SCHEMA_VERSION


def test_each_class_constructs_with_expected_uids() -> None:
    cases = [
        (Authentication(time=SAMPLE_MS, metadata=_metadata()), 3002, 3),
        (ProcessActivity(time=SAMPLE_MS, metadata=_metadata()), 1007, 1),
        (NetworkActivity(time=SAMPLE_MS, metadata=_metadata()), 4001, 4),
        (FileSystemActivity(time=SAMPLE_MS, metadata=_metadata()), 1001, 1),
        (ScheduledJobActivity(time=SAMPLE_MS, metadata=_metadata()), 1006, 1),
        (DetectionFinding(time=SAMPLE_MS, metadata=_metadata()), 2004, 2),
    ]
    for event, class_uid, category_uid in cases:
        assert event.class_uid == class_uid
        assert event.category_uid == category_uid


def test_minimal_construction_uses_base_defaults() -> None:
    event = NetworkActivity(time=SAMPLE_MS, metadata=_metadata())
    assert event.time == SAMPLE_MS
    assert event.activity_id == 1
    assert event.severity_id == 1
    assert event.raw_data is None
    assert event.unmapped == {}


def test_type_uid_is_class_uid_times_100_plus_activity() -> None:
    assert Authentication(time=SAMPLE_MS, metadata=_metadata()).type_uid == 300201
    assert (
        Authentication(time=SAMPLE_MS, metadata=_metadata(), activity_id=2).type_uid
        == 300202
    )
    assert ProcessActivity(time=SAMPLE_MS, metadata=_metadata()).type_uid == 100701


def test_stale_type_uid_in_input_is_recomputed() -> None:
    payload = Authentication(time=SAMPLE_MS, metadata=_metadata()).model_dump_json()
    tampered = payload.replace('"type_uid":300201', '"type_uid":999')
    assert Authentication.model_validate_json(tampered).type_uid == 300201


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Authentication(
            time=datetime(2026, 10, 27, 12, 0, 0),
            metadata=_metadata(),
        )


def test_aware_datetime_converts_to_epoch_milliseconds() -> None:
    event = Authentication(time=SAMPLE_TIME, metadata=_metadata())
    assert event.time == SAMPLE_MS


def test_epoch_seconds_look_below_the_year_2000_floor() -> None:
    assert MIN_TIME_MS == 946684800000
    with pytest.raises(ValidationError, match="epoch seconds"):
        Authentication(time=1793102400, metadata=_metadata())


def test_pre_2000_datetime_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Authentication(
            time=datetime(1999, 12, 31, 23, 59, 59, tzinfo=UTC),
            metadata=_metadata(),
        )


def test_negative_epoch_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Authentication(time=-1, metadata=_metadata())


def test_severity_99_other_is_allowed() -> None:
    event = DetectionFinding(time=SAMPLE_MS, metadata=_metadata(), severity_id=99)
    assert event.severity_id == 99


def test_severity_7_is_rejected() -> None:
    with pytest.raises(ValidationError, match="severity_id"):
        DetectionFinding(time=SAMPLE_MS, metadata=_metadata(), severity_id=7)


def test_netbios_user_spellings_map_to_one_key() -> None:
    spellings = ["EXAMPLE\\JDoe", "example\\jdoe", "  EXAMPLE\\JDOE  "]
    keys = {
        Authentication(
            time=SAMPLE_MS,
            metadata=_metadata(),
            actor=_user(spelling),
            device={"hostname": "web01.example.com"},
        ).entity_keys.user
        for spelling in spellings
    }
    assert keys == {"example\\jdoe"}


def test_upn_spellings_map_to_one_key() -> None:
    spellings = ["JDOE@EXAMPLE.COM", "jdoe@example.com"]
    keys = {
        Authentication(
            time=SAMPLE_MS,
            metadata=_metadata(),
            actor=_user(spelling),
        ).entity_keys.user
        for spelling in spellings
    }
    assert keys == {"example.com\\jdoe"}


def test_bare_user_combines_with_domain() -> None:
    event = Authentication(
        time=SAMPLE_MS,
        metadata=_metadata(),
        actor=_user("JDOE", "EXAMPLE.COM"),
    )
    assert event.entity_keys.user == "example.com\\jdoe"


def test_placeholder_user_gives_no_user_key() -> None:
    for spelling in ["-", "n/a", "UNKNOWN", ""]:
        event = Authentication(
            time=SAMPLE_MS,
            metadata=_metadata(),
            actor=_user(spelling, "example.com"),
        )
        assert event.entity_keys.user is None


def test_host_spellings_map_to_one_key() -> None:
    spellings = ["WEB01", "web01.example.com", " WEB01.EXAMPLE.COM ", "WEB01$"]
    keys = {
        NetworkActivity(
            time=SAMPLE_MS,
            metadata=_metadata(),
            device={"hostname": spelling, "ip": "192.0.2.10"},
        ).entity_keys.host
        for spelling in spellings
    }
    assert keys == {"web01"}


def test_ip_address_gives_no_host_key() -> None:
    for value in ["10.0.0.5", "10.9.9.9"]:
        event = NetworkActivity(
            time=SAMPLE_MS,
            metadata=_metadata(),
            device={"hostname": value, "ip": value},
        )
        assert event.entity_keys.host is None
        assert event.entity_keys.ip == value


def test_placeholder_hostname_gives_no_host_key() -> None:
    for value in ["-", "n/a", "unknown"]:
        event = NetworkActivity(
            time=SAMPLE_MS,
            metadata=_metadata(),
            device={"hostname": value},
        )
        assert event.entity_keys.host is None


def test_invalid_ip_gives_no_ip_key() -> None:
    event = NetworkActivity(
        time=SAMPLE_MS,
        metadata=_metadata(),
        device={"hostname": "web01.example.com", "ip": "not-an-ip"},
    )
    assert event.entity_keys.ip is None


def test_ipv4_mapped_ipv6_unwraps_to_ipv4() -> None:
    event = NetworkActivity(
        time=SAMPLE_MS,
        metadata=_metadata(),
        device={"hostname": "web01.example.com", "ip": "::ffff:10.0.0.5"},
    )
    assert event.entity_keys.ip == "10.0.0.5"


def test_placeholder_device_ip_does_not_hide_endpoint_ip() -> None:
    event = NetworkActivity(
        time=SAMPLE_MS,
        metadata=_metadata(),
        device={"hostname": "web01.example.com", "ip": "-"},
        src_endpoint={"ip": "198.51.100.23", "port": 4444},
        dst_endpoint={"ip": "203.0.113.7", "port": 443},
    )
    assert event.entity_keys.ip is None
    assert event.entity_keys.src_ip == "198.51.100.23"
    assert event.entity_keys.dst_ip == "203.0.113.7"


def test_brute_force_shape_keeps_each_endpoint_ip() -> None:
    event = NetworkActivity(
        time=SAMPLE_MS,
        metadata=_metadata(),
        device={"hostname": "web01.example.com"},
        src_endpoint={"ip": "198.51.100.23", "port": 4444},
        dst_endpoint={"ip": "203.0.113.7", "port": 443},
    )
    assert event.entity_keys.ip is None
    assert event.entity_keys.src_ip == "198.51.100.23"
    assert event.entity_keys.dst_ip == "203.0.113.7"


def test_json_round_trip_preserves_event() -> None:
    event = ProcessActivity(
        time=SAMPLE_TIME,
        metadata={**_metadata(), "uid": "alert-1"},
        severity_id=4,
        actor=_user("EXAMPLE\\jdoe"),
        device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
        process={
            "pid": 1234,
            "name": "powershell.exe",
            "cmd_line": "powershell -enc x",
            "file": {"path": "C:\\Windows\\System32\\powershell.exe"},
            "parent_process": {"pid": 4, "name": "services.exe"},
        },
        raw_data={"original": "event"},
        unmapped={"wazuh_rule": "100002"},
    )
    restored = ProcessActivity.model_validate_json(event.model_dump_json())
    assert restored == event
    assert restored.type_uid == 100701
    assert restored.time == SAMPLE_MS
    assert restored.entity_keys.user == "example\\jdoe"
    assert restored.entity_keys.host == "web01"
    assert restored.entity_keys.ip == "192.0.2.10"
    assert restored.raw_data == '{"original": "event"}'
    assert isinstance(restored.process, Process)
    assert restored.process is not None
    assert restored.process.file is not None
    assert restored.process.file.name == "powershell.exe"
    assert restored.process.parent_process is not None
    assert restored.process.parent_process.pid == 4


def test_discriminated_union_parses_each_class_from_dict() -> None:
    cases = [
        (3002, 3, Authentication),
        (1007, 1, ProcessActivity),
        (4001, 4, NetworkActivity),
        (1001, 1, FileSystemActivity),
        (1006, 1, ScheduledJobActivity),
        (2004, 2, DetectionFinding),
    ]
    for class_uid, category_uid, cls in cases:
        parsed = EVENT_ADAPTER.validate_python(
            {
                "class_uid": class_uid,
                "category_uid": category_uid,
                "time": SAMPLE_MS,
                "metadata": _metadata(),
            }
        )
        assert isinstance(parsed, cls)
        assert parsed.class_uid == class_uid


def test_file_name_derives_from_path() -> None:
    event = FileSystemActivity(
        time=SAMPLE_MS,
        metadata=_metadata(),
        file={"path": "/etc/cron.d/evil"},
    )
    assert event.file is not None
    assert event.file.name == "evil"


def test_authentication_status_fields() -> None:
    event = Authentication(
        time=SAMPLE_MS,
        metadata=_metadata(),
        status="Failure",
        status_id=2,
    )
    assert (event.status, event.status_id) == ("Failure", 2)


def test_network_action_fields() -> None:
    event = NetworkActivity(
        time=SAMPLE_MS,
        metadata=_metadata(),
        activity_id=1,
        action="Allowed",
        action_id=1,
    )
    assert (event.action, event.action_id) == ("Allowed", 1)
    with pytest.raises(ValidationError, match="action_id"):
        NetworkActivity(time=SAMPLE_MS, metadata=_metadata(), action_id=7)
