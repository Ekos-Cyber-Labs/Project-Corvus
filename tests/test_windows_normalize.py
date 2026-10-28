"""Tests for the Windows normalizer in corvus/normalize/windows.py."""

import json
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from corvus.normalize.windows import (
    SECURITY_CHANNEL,
    SYSMON_CHANNEL,
    TASKSCHEDULER_CHANNEL,
    UnmappedEvent,
    WindowsReadStats,
    extract_evtx_parts,
    extract_json_parts,
    iter_dataset_file,
    make_uid,
    normalize_event,
    parse_windows_time,
    read_dataset_file,
    read_otrf_archive,
    sanitize_record,
)
from tests.fixtures import windows_events as fx

UID_BASE = "test-fixture"

#: Envelope keys placed structurally per layout (channel, id, host, time).
FLAT_ENVELOPE = {
    "Channel",
    "EventID",
    "EventIdx",
    "EventRecordID",
    "Computer",
    "Hostname",
    "TimeCreated",
    "UtcTime",
    "@timestamp",
}
OLD_BEAT_ENVELOPE = {
    "log_name",
    "event_id",
    "record_number",
    "computer_name",
    "@timestamp",
    "event_data",
}
WINLOG_ENVELOPE = {
    "winlog",
    "@timestamp",
    "channel",
    "event_id",
    "record_id",
    "computer_name",
    "event_data",
}


def _normalize_record(
    record: dict[str, Any], lineno: int = 1, uid_base: str = UID_BASE
):
    """Run a hand-made record through extraction plus normalization."""
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, lineno
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid(uid_base, record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )


def _input_keys(record: dict[str, Any]) -> set[str]:
    """Every field key a record carries, across nesting levels."""
    keys = set(record) - {"event_data", "winlog"}
    payload = record.get("event_data")
    if isinstance(payload, dict):
        keys |= set(payload)
    winlog = record.get("winlog")
    if isinstance(winlog, dict):
        keys |= set(winlog) - {"event_data"}
        nested = winlog.get("event_data")
        if isinstance(nested, dict):
            keys |= set(nested)
    return keys


def _check_no_drop(record: dict[str, Any], envelope: set[str], typed: set[str]) -> None:
    """Assert every input field ends up typed or in unmapped, never dropped."""
    event = _normalize_record(record)
    available = _input_keys(record)
    assert set(event.unmapped) <= available
    assert available <= set(envelope) | set(typed) | set(event.unmapped)


def _write_zip(path: Path, members: dict[str, list[str]]) -> Path:
    """Write a zip of JSON-lines members; each value is a list of raw lines."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, lines in members.items():
            archive.writestr(name, "\n".join(lines) + "\n")
    return path


def test_sysmon_1_maps_to_process_activity() -> None:
    event = _normalize_record(fx.flat_sysmon_process())
    assert event.class_uid == 1007
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.metadata.product.name == "Sysmon"
    assert event.time == fx.SYS_MS
    assert event.process is not None
    assert event.process.pid == 4321
    assert event.process.name == "powershell.exe"
    assert event.process.cmd_line == "powershell.exe -NoProfile -Command Get-Process"
    assert event.process.parent_process is not None
    assert event.process.parent_process.pid == 1234
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "jdoe"
    assert event.device is not None
    assert event.device.hostname == "web01.example.com"
    assert event.entity_keys.user == "example\\jdoe"
    assert event.entity_keys.host == "web01"


def test_sysmon_3_maps_to_network_activity() -> None:
    event = _normalize_record(fx.flat_sysmon_network())
    assert event.class_uid == 4001
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "192.0.2.10"
    assert event.src_endpoint.port == 52310
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == "203.0.113.7"
    assert event.dst_endpoint.port == 443
    assert event.entity_keys.src_ip == "192.0.2.10"
    assert event.entity_keys.dst_ip == "203.0.113.7"
    assert event.actor is not None and event.actor.process is not None
    assert event.actor.process.pid == 4321
    assert event.actor.process.name == "powershell.exe"
    assert event.unmapped["Protocol"] == "tcp"


def test_sysmon_11_maps_to_file_system_activity() -> None:
    event = _normalize_record(fx.flat_sysmon_file())
    assert event.class_uid == 1001
    assert event.file is not None
    assert event.file.path == "C:\\Users\\jdoe\\AppData\\Local\\Temp\\dropper.bin"
    assert event.file.name == "dropper.bin"
    assert event.actor is not None and event.actor.process is not None
    assert event.actor.process.pid == 4321


def test_security_4624_maps_to_successful_authentication() -> None:
    event = _normalize_record(fx.flat_security_logon(success=True))
    assert event.class_uid == 3002
    assert event.metadata.log_name == SECURITY_CHANNEL
    assert event.metadata.product.name == "Microsoft Windows"
    assert event.status == "Success"
    assert event.status_id == 1
    assert event.logon_type == "Network"
    assert event.logon_type_id == 3
    assert event.unmapped["LogonType"] == 3
    assert event.unmapped["WorkstationName"] == "client01.example.com"
    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "198.51.100.23"


def test_security_4625_maps_to_failed_authentication() -> None:
    event = _normalize_record(fx.flat_security_logon(success=False))
    assert event.class_uid == 3002
    assert event.status == "Failure"
    assert event.status_id == 2
    assert event.logon_type == "Network"
    assert event.logon_type_id == 3


def test_security_4698_maps_to_scheduled_job() -> None:
    event = _normalize_record(fx.flat_security_task())
    assert event.class_uid == 1006
    assert event.metadata.product.name == "Microsoft Windows"
    assert event.job is not None
    assert event.job.name == "\\Example\\NightlySync"
    assert "TaskContentNew" in event.unmapped


def test_taskscheduler_106_maps_to_scheduled_job() -> None:
    event = _normalize_record(fx.flat_taskscheduler_106())
    assert event.class_uid == 1006
    assert event.metadata.log_name == TASKSCHEDULER_CHANNEL
    assert event.job is not None
    assert event.job.name == "\\Example\\NightlySync"
    assert "UserData" in event.unmapped


def test_unmapped_channel_event_raises_with_key() -> None:
    record = fx.flat_unmapped()
    with pytest.raises(UnmappedEvent) as excinfo:
        _normalize_record(record)
    assert excinfo.value.key == ("Security", 4688)


def test_unparseable_time_counts_as_unmapped() -> None:
    record = fx.flat_sysmon_process()
    record["TimeCreated"] = "not-a-time"
    with pytest.raises(UnmappedEvent) as excinfo:
        _normalize_record(record)
    assert excinfo.value.key == (SYSMON_CHANNEL, 1)


def test_missing_optional_fields_still_map() -> None:
    event = _normalize_record(fx.flat_minimal_process())
    assert event.class_uid == 1007
    assert event.process is None
    assert event.actor is None
    assert event.device is not None


def test_unicode_command_line_preserved() -> None:
    event = _normalize_record(fx.flat_unicode_process())
    assert event.class_uid == 1007
    assert event.process is not None
    assert event.process.cmd_line == (
        "powershell.exe -Command Write-Host 'héllo wörld 数据 🎯'"
    )
    assert event.process.name == "outilβ.exe"


def test_offset_timezone_converted_to_utc() -> None:
    assert parse_windows_time("2024-05-02T16:03:00+02:00") == fx.SYS_MS
    assert parse_windows_time(fx.SYS_UTC) == fx.SYS_MS
    assert parse_windows_time(fx.SYS_UTCTIME) == fx.SYS_MS
    assert parse_windows_time(fx.SYS_MS) == fx.SYS_MS


def test_object_event_id_counts_under_its_text() -> None:
    """Producers that render EventID as {"#text": N} count under N, not 0."""
    record = fx.evtx_sysmon_process()
    system = record["Event"]["System"]
    assert isinstance(system, dict)
    system["EventID"] = {"#text": "1"}
    channel, event_id, _, _, _, _ = extract_evtx_parts(record)
    assert channel == SYSMON_CHANNEL
    assert event_id == 1


def test_uid_is_stable_and_unique() -> None:
    assert make_uid("rel#path", 7) == make_uid("rel#path", 7)
    assert make_uid("rel#path", 7) != make_uid("rel#path", 8)
    assert make_uid("rel#path", 7) != make_uid("other#path", 7)
    assert len(make_uid("rel#path", 7)) == 16


def test_evtx_nested_shape_maps_like_flat() -> None:
    channel, event_id, record_id, fields, computer, raw_time = extract_evtx_parts(
        fx.evtx_sysmon_process()
    )
    assert channel == SYSMON_CHANNEL
    assert event_id == 1
    assert record_id == 201
    assert computer == "web01.example.com"
    event = normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid(UID_BASE, record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(
            {
                "System": fx.evtx_sysmon_process()["Event"]["System"],
                "EventData": fields,
            }
        ),
    )
    assert event.class_uid == 1007
    assert event.time == fx.SYS_MS
    assert event.process is not None
    assert event.process.pid == 4321
    assert event.process.name == "cmd.exe"


def test_reader_counts_unmapped_and_malformed_per_key(tmp_path: Path) -> None:
    lines = [
        json.dumps(fx.flat_sysmon_process()),
        json.dumps(fx.flat_unmapped()),
        json.dumps(fx.flat_unmapped()),
        "{not json",
        "[1, 2]",
        "",
    ]
    archive = _write_zip(tmp_path / "mixed.zip", {"events.json": lines})
    result = read_otrf_archive(archive, dataset_rel="mixed.zip")
    assert len(result.events) == 1
    assert result.unmapped == {("Security", 4688): 2, ("unknown", 0): 2}
    assert result.unsupported == 0


def test_pcap_only_archive_is_unsupported_not_an_error(tmp_path: Path) -> None:
    archive = tmp_path / "capture.zip"
    with zipfile.ZipFile(archive, "w") as holder:
        holder.writestr("capture.cap", b"fake-pcap-bytes")
    result = read_otrf_archive(archive, dataset_rel="capture.zip")
    assert result.events == []
    assert result.unmapped == {}
    assert result.unsupported == 1


def test_tar_gz_archive_reads_json_lines(tmp_path: Path) -> None:
    archive = tmp_path / "host.tar.gz"
    payload = "\n".join(
        [
            json.dumps(fx.flat_security_logon(success=True)),
            json.dumps(fx.flat_unmapped()),
        ]
    ).encode()
    with tarfile.open(archive, "w:gz") as holder:
        info = tarfile.TarInfo("events.json")
        info.size = len(payload)
        holder.addfile(info, BytesIO(payload))
    result = read_dataset_file(archive, dataset_rel="host.tar.gz")
    assert len(result.events) == 1
    assert result.unmapped == {("Security", 4688): 1}
    assert result.unsupported == 0
    assert result.events[0].class_uid == 3002


def test_file_name_technique_id_never_enters_records(tmp_path: Path) -> None:
    """Ground-truth isolation: the source file name carries an ATT&CK id."""
    record = fx.flat_security_logon(success=True)
    record["log"] = {"file": {"path": "C:/data/T1003_credprobe_fixture.zip"}}
    record["path"] = "C:/data/T1003_credprobe_fixture.zip"
    record["log.file.path"] = "C:/data/T1003_credprobe_fixture.zip"
    record["@metadata"] = {"beat": "T1003_credprobe_fixture"}
    archive = _write_zip(
        tmp_path / "T1003_credprobe_fixture.zip", {"events.json": [json.dumps(record)]}
    )
    rel = "datasets/atomic/windows/fake/T1003_credprobe_fixture.zip"
    first = read_otrf_archive(archive, dataset_rel=rel)
    second = read_otrf_archive(archive, dataset_rel=rel)
    assert len(first.events) == 1
    assert first.events[0].class_uid == 3002
    assert [e.metadata.uid for e in first.events] == [
        e.metadata.uid for e in second.events
    ]
    for event in first.events:
        dump = event.model_dump_json()
        assert "T1003" not in dump
        assert "credprobe" not in dump
        assert set(event.unmapped) == {"LogonType", "WorkstationName"}
    raw = json.loads(first.events[0].raw_data or "{}")
    assert "log" not in raw
    assert "path" not in raw
    assert "log.file.path" not in raw
    assert "@metadata" not in raw


def test_replay_products_land_in_the_source_category_map() -> None:
    """The explicit siem.py source map covers the replay products/channels."""
    from corvus.adapters.siem import FakeAdapter

    events = [
        _normalize_record(fx.flat_sysmon_process()),
        _normalize_record(fx.flat_security_logon(success=True)),
        _normalize_record(fx.flat_taskscheduler_106()),
    ]
    inventory = FakeAdapter(events).describe_sources()
    by_source = {entry.source: entry.category for entry in inventory.sources}
    assert by_source[f"Sysmon:{SYSMON_CHANNEL}"] == "endpoint process"
    assert by_source[f"Microsoft Windows:{SECURITY_CHANNEL}"] == "authentication"
    assert by_source[f"Microsoft Windows:{TASKSCHEDULER_CHANNEL}"] == "endpoint process"


def test_lowercase_channel_maps_with_canonical_log_name() -> None:
    """OTRF archives spell the Security channel lowercase; still map it."""
    event = _normalize_record(fx.flat_lowercase_channel_logon())
    assert event.class_uid == 3002
    assert event.metadata.log_name == SECURITY_CHANNEL
    assert event.status == "Success"
    assert event.logon_type_id == 3


def test_old_beat_layout_maps_sysmon_network() -> None:
    """Older winlogbeat layout (payload under event_data) maps fully."""
    event = _normalize_record(fx.old_beat_sysmon_network())
    assert event.class_uid == 4001
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.metadata.product.name == "Sysmon"
    assert event.time == fx.SYS_MS
    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "192.0.2.10"
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.ip == "203.0.113.7"
    assert event.actor is not None and event.actor.process is not None
    assert event.actor.process.pid == 4321
    assert event.unmapped["Protocol"] == "tcp"
    assert "message" in event.unmapped


def test_old_beat_layout_maps_security_logon() -> None:
    """Older winlogbeat layout of a 4624 maps with typed logon fields."""
    event = _normalize_record(fx.old_beat_security_logon())
    assert event.class_uid == 3002
    assert event.metadata.log_name == SECURITY_CHANNEL
    assert event.status == "Success"
    assert event.logon_type == "Network"
    assert event.logon_type_id == 3
    assert event.unmapped["WorkstationName"] == "client01.example.com"


def test_winlog_layout_maps_sysmon_file() -> None:
    """Newer nested winlog layout maps to File System Activity."""
    event = _normalize_record(fx.winlog_sysmon_file())
    assert event.class_uid == 1001
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.file is not None
    assert event.file.path == "C:\\Temp\\dropper.bin"
    assert event.actor is not None and event.actor.process is not None
    assert event.actor.process.pid == 4321
    assert "provider_name" in event.unmapped


def test_sysmon_1_drops_no_field() -> None:
    _check_no_drop(
        fx.flat_sysmon_process(),
        FLAT_ENVELOPE,
        {
            "Image",
            "ProcessId",
            "CommandLine",
            "ParentImage",
            "ParentProcessId",
            "User",
            "UtcTime",
        },
    )


def test_sysmon_3_drops_no_field() -> None:
    _check_no_drop(
        fx.flat_sysmon_network(),
        FLAT_ENVELOPE,
        {
            "Image",
            "ProcessId",
            "User",
            "SourceIp",
            "SourcePort",
            "DestinationIp",
            "DestinationPort",
            "UtcTime",
        },
    )


def test_sysmon_11_drops_no_field() -> None:
    _check_no_drop(
        fx.flat_sysmon_file(),
        FLAT_ENVELOPE,
        {"Image", "ProcessId", "User", "TargetFilename", "UtcTime"},
    )


def test_security_4624_drops_no_field() -> None:
    _check_no_drop(
        fx.flat_security_logon(success=True),
        FLAT_ENVELOPE,
        {
            "TargetUserName",
            "TargetDomainName",
            "LogonType",
            "IpAddress",
            "IpPort",
            "TimeCreated",
        },
    )


def test_security_4698_drops_no_field() -> None:
    _check_no_drop(
        fx.flat_security_task(),
        FLAT_ENVELOPE,
        {"TaskName", "SubjectUserName", "SubjectDomainName", "TimeCreated"},
    )


def test_taskscheduler_106_drops_no_field() -> None:
    _check_no_drop(
        fx.flat_taskscheduler_106(),
        FLAT_ENVELOPE,
        {"TaskName", "User", "TimeCreated"},
    )


def test_old_beat_layout_drops_no_field() -> None:
    _check_no_drop(
        fx.old_beat_sysmon_network(),
        OLD_BEAT_ENVELOPE,
        {
            "Image",
            "ProcessId",
            "User",
            "SourceIp",
            "SourcePort",
            "DestinationIp",
            "DestinationPort",
            "UtcTime",
        },
    )


def test_iter_dataset_file_streams_with_stats(tmp_path: Path) -> None:
    """The streaming iterator yields events while filling caller stats."""
    lines = [
        json.dumps(fx.flat_sysmon_process()),
        json.dumps(fx.flat_unmapped()),
        "{not json",
    ]
    archive = _write_zip(tmp_path / "mixed.zip", {"events.json": lines})
    stats = WindowsReadStats()
    events = list(iter_dataset_file(archive, dataset_rel="mixed.zip", stats=stats))
    assert len(events) == 1
    assert events[0].class_uid == 1007
    assert stats.unmapped == {("Security", 4688): 1, ("unknown", 0): 1}
    assert stats.unsupported == 0
    collected = read_dataset_file(archive, dataset_rel="mixed.zip")
    assert [e.metadata.uid for e in events] == [
        e.metadata.uid for e in collected.events
    ]
    assert collected.unmapped == stats.unmapped
