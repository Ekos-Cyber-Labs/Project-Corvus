"""Tests for the Windows normalizer in corvus/normalize/windows.py."""

import json
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from corvus.normalize.windows import (
    POWERSHELL_CHANNEL,
    SECURITY_CHANNEL,
    SYSMON_CHANNEL,
    SYSTEM_CHANNEL,
    TASKSCHEDULER_CHANNEL,
    WINDOWS_POWERSHELL_CHANNEL,
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


def test_evtx_missing_channel_counts_under_provider_name() -> None:
    """Channel-less ETW records count under the System.Provider name."""
    channel, event_id, record_id, fields, computer, raw_time = extract_evtx_parts(
        fx.evtx_rpc_no_channel()
    )
    assert channel == "Microsoft-Windows-RPC"
    assert event_id == 5
    with pytest.raises(UnmappedEvent) as excinfo:
        normalize_event(
            channel=channel,
            event_id=event_id,
            fields=sanitize_record(fields),
            computer=computer,
            uid=make_uid(UID_BASE, record_id),
            raw_time=raw_time,
            raw_record=sanitize_record(fx.evtx_rpc_no_channel()["Event"]),
        )
    assert excinfo.value.key == ("Microsoft-Windows-RPC", 5)


def test_logon_type_12_and_13_pass_straight_through() -> None:
    """Windows LogonType 12/13 keep their OCSF ids; the rest become 99."""
    for logon_type, expected_id, expected_name in (
        (12, 12, "Cached Remote Interactive"),
        (13, 13, "Cached Unlock"),
        (42, 99, "Other"),
    ):
        record = fx.flat_security_logon(success=True)
        record["LogonType"] = logon_type
        event = _normalize_record(record)
        assert event.logon_type_id == expected_id
        assert event.logon_type == expected_name
        assert event.unmapped["LogonType"] == logon_type


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


def test_bare_json_lines_file_reads_flat_and_nested(tmp_path: Path) -> None:
    path = tmp_path / "events.json"
    path.write_text(
        "\n".join(
            [
                json.dumps(fx.flat_sysmon_process()),
                json.dumps(fx.winlog_sysmon_file()),
                json.dumps(fx.flat_unmapped()),
            ]
        )
        + "\n"
    )
    result = read_dataset_file(path, dataset_rel="events.json")
    assert len(result.events) == 2
    assert {event.class_uid for event in result.events} == {1007, 1001}
    assert result.unmapped == {("Security", 4688): 1}
    assert result.unsupported == 0


def test_empty_json_lines_file_yields_no_events(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("")
    result = read_dataset_file(path, dataset_rel="empty.json")
    assert result.events == []
    assert result.unmapped == {}
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
        _normalize_record(fx.flat_powershell_script()),
        _normalize_record(fx.flat_sysmon_registry_value()),
        _normalize_record(fx.flat_security_service()),
        _normalize_record(fx.flat_service_install(channel="System")),
    ]
    inventory = FakeAdapter(events).describe_sources()
    by_source = {entry.source: entry.category for entry in inventory.sources}
    assert by_source[f"Sysmon:{SYSMON_CHANNEL}"] == "endpoint process"
    assert by_source[f"Microsoft Windows:{SECURITY_CHANNEL}"] == "authentication"
    assert by_source[f"Microsoft Windows:{TASKSCHEDULER_CHANNEL}"] == "endpoint process"
    assert by_source[f"Microsoft Windows:{POWERSHELL_CHANNEL}"] == "endpoint process"
    assert by_source[f"Microsoft Windows:{SYSTEM_CHANNEL}"] == "endpoint process"
    classes = {entry.source: entry.classes for entry in inventory.sources}
    assert 201002 in classes[f"Sysmon:{SYSMON_CHANNEL}"]
    assert 201004 in classes[f"Microsoft Windows:{SECURITY_CHANNEL}"]
    assert classes[f"Microsoft Windows:{SYSTEM_CHANNEL}"] == [201004]


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


def test_sysmon_10_maps_to_process_open() -> None:
    event = _normalize_record(fx.flat_sysmon_access())
    assert event.class_uid == 1007
    assert event.activity_id == 3
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.metadata.product.name == "Sysmon"
    assert event.time == fx.SYS_MS
    assert event.actor is not None and event.actor.process is not None
    assert event.actor.process.pid == 4321
    assert event.actor.process.name == "powershell.exe"
    assert event.process is not None
    assert event.process.pid == 888
    assert event.process.name == "lsass.exe"
    assert event.process.file is not None
    assert event.process.file.path == "C:\\Windows\\System32\\lsass.exe"
    assert event.actual_permissions == "0x1010"
    assert isinstance(event.actual_permissions, str)
    assert "CallTrace" in event.unmapped
    _check_no_drop(
        fx.flat_sysmon_access(),
        FLAT_ENVELOPE,
        {
            "Image",
            "ProcessId",
            "User",
            "SourceImage",
            "SourceProcessId",
            "TargetImage",
            "TargetProcessId",
            "GrantedAccess",
            "UtcTime",
        },
    )


def test_powershell_4104_maps_to_script_activity() -> None:
    event = _normalize_record(fx.flat_powershell_script())
    assert event.class_uid == 1009
    assert event.category_uid == 1
    assert event.activity_id == 1
    assert event.metadata.log_name == POWERSHELL_CHANNEL
    assert event.metadata.product.name == "Microsoft Windows"
    assert event.time == fx.SYS_MS
    assert event.script is not None
    assert event.script.script_content == "Get-Process | Where-Object { $_.CPU -gt 10 }"
    assert event.script.uid == "{cccccccc-9999-aaaa-bbbb-cccccccccccc}"
    assert event.script.type_id == 2
    assert event.script.type == "PowerShell"
    assert event.unmapped["MessageNumber"] == 1
    assert event.unmapped["MessageTotal"] == 1
    _check_no_drop(
        fx.flat_powershell_script(),
        FLAT_ENVELOPE,
        {"User", "ScriptBlockText", "ScriptBlockId"},
    )


def test_powershell_split_script_block_keeps_every_message() -> None:
    events = [_normalize_record(record) for record in fx.flat_powershell_script_split()]
    assert len(events) == 3
    assert {event.script.uid for event in events} == {
        "{dddddddd-0000-1111-2222-333333333333}"
    }
    assert [event.unmapped["MessageNumber"] for event in events] == [1, 2, 3]
    assert all(event.unmapped["MessageTotal"] == 3 for event in events)
    assert "".join(event.script.script_content for event in events) == (
        "$data = Get-Process |Where-Object { $_.CPU -gt 10 } |Select-Object Name, CPU"
    )


def test_unmapped_ids_still_count_per_channel_and_id(tmp_path: Path) -> None:
    """New mappings do not change counting for other event ids."""
    lines = [
        json.dumps(fx.flat_sysmon_access()),
        json.dumps(fx.flat_powershell_script()),
        json.dumps(fx.flat_unmapped(event_id=7, channel=SYSMON_CHANNEL)),
        json.dumps(fx.flat_unmapped(event_id=4105, channel=POWERSHELL_CHANNEL)),
        json.dumps(fx.flat_unmapped()),
    ]
    archive = _write_zip(tmp_path / "mixed2.zip", {"events.json": lines})
    result = read_dataset_file(archive, dataset_rel="mixed2.zip")
    assert len(result.events) == 2
    assert {event.class_uid for event in result.events} == {1007, 1009}
    assert result.unmapped == {
        (SYSMON_CHANNEL, 7): 1,
        (POWERSHELL_CHANNEL, 4105): 1,
        ("Security", 4688): 1,
    }


def test_powershell_4103_maps_to_script_activity() -> None:
    event = _normalize_record(fx.flat_powershell_module())
    assert event.class_uid == 1009
    assert event.activity_id == 1
    assert event.metadata.log_name == POWERSHELL_CHANNEL
    assert event.script is not None
    assert (
        event.script.script_content == 'CommandInvocation(Get-Process): "Get-Process"'
    )
    assert event.script.uid is None
    assert event.script.type_id == 2
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "jdoe"
    assert event.actor.user.domain == "EXAMPLE"
    assert "ContextInfo" in event.unmapped
    _check_no_drop(
        fx.flat_powershell_module(),
        FLAT_ENVELOPE,
        {"AccountName", "Domain", "Payload"},
    )


def test_windows_powershell_800_maps_to_script_activity() -> None:
    event = _normalize_record(fx.flat_windows_powershell_pipeline())
    assert event.class_uid == 1009
    assert event.metadata.log_name == WINDOWS_POWERSHELL_CHANNEL
    assert event.script is not None
    assert "Get-Process" in (event.script.script_content or "")


def test_windows_powershell_600_stays_unmapped() -> None:
    with pytest.raises(UnmappedEvent) as excinfo:
        _normalize_record(fx.flat_windows_powershell_provider())
    assert excinfo.value.key == (WINDOWS_POWERSHELL_CHANNEL, 600)


def test_sysmon_12_create_maps_to_registry_key_activity() -> None:
    event = _normalize_record(fx.flat_sysmon_registry_key())
    assert event.class_uid == 201001
    assert event.category_uid == 1
    assert event.activity_id == 1
    assert event.type_uid == 20100101
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.metadata.product.name == "Sysmon"
    assert event.time == fx.SYS_MS
    assert event.reg_key is not None
    assert event.reg_key.path == "HKLM\\SOFTWARE\\ExampleCorp\\ExampleApp"
    assert event.prev_reg_key is None
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "SYSTEM"
    assert event.actor.user.domain == "NT AUTHORITY"
    assert event.actor.process is not None
    assert event.actor.process.pid == 4321
    assert event.actor.process.name == "regedit.exe"
    assert event.unmapped["EventType"] == "INFO"
    assert "EventType: CreateKey" in event.unmapped["Message"]
    assert event.unmapped["RuleName"] == "-"
    assert event.entity_keys.user == "nt authority\\system"
    assert event.entity_keys.host == "web01"
    _check_no_drop(
        fx.flat_sysmon_registry_key(),
        FLAT_ENVELOPE,
        {
            "TargetObject",
            "Image",
            "ProcessId",
            "AccountName",
            "Domain",
            "UtcTime",
        },
    )


def test_sysmon_12_deletekey_maps_to_delete() -> None:
    """The op comes from the Message line when EventType is INFO."""
    event = _normalize_record(fx.flat_sysmon_registry_key(event_type="DeleteKey"))
    assert event.class_uid == 201001
    assert event.activity_id == 4
    assert event.reg_key is not None
    assert event.reg_key.path == "HKLM\\SOFTWARE\\ExampleCorp\\ExampleApp"
    assert event.unmapped["EventType"] == "INFO"
    # Other NXLog files keep a real EventType field: same outcome.
    field_op = fx.flat_sysmon_registry_key()
    field_op["EventType"] = "DeleteKey"
    del field_op["Message"]
    event = _normalize_record(field_op)
    assert event.class_uid == 201001
    assert event.activity_id == 4


def test_sysmon_12_deletevalue_maps_to_registry_value_delete() -> None:
    """A value delete is a Registry Value Activity, not a key record."""
    event = _normalize_record(fx.flat_sysmon_registry_key(event_type="DeleteValue"))
    assert event.class_uid == 201002
    assert event.activity_id == 4
    assert event.type_uid == 20100204
    assert event.reg_value is not None
    assert event.reg_value.path == "HKLM\\SOFTWARE\\ExampleCorp\\ExampleApp"
    assert event.reg_value.name == "ExampleApp"
    assert event.unmapped["EventType"] == "INFO"


def test_sysmon_12_filler_event_type_defaults_to_create() -> None:
    """INFO with no Message op stays Create with the raw value kept."""
    record = fx.flat_sysmon_registry_key()
    record["Message"] = "Registry object added or deleted:\r\nRuleName: -\r\n"
    event = _normalize_record(record)
    assert event.class_uid == 201001
    assert event.activity_id == 1
    assert event.reg_key is not None
    assert event.unmapped["EventType"] == "INFO"


def test_sysmon_12_other_known_ops_route_to_their_class() -> None:
    """Defensive branches: value ops to Value, RenameKey to Key Rename."""
    value = _normalize_record(fx.flat_sysmon_registry_key(event_type="SetValue"))
    assert value.class_uid == 201002
    assert value.activity_id == 2
    rename = _normalize_record(fx.flat_sysmon_registry_key(event_type="RenameKey"))
    assert rename.class_uid == 201001
    assert rename.activity_id == 5


def test_sysmon_13_maps_to_registry_value_activity() -> None:
    event = _normalize_record(fx.flat_sysmon_registry_value())
    assert event.class_uid == 201002
    assert event.category_uid == 1
    assert event.activity_id == 2
    assert event.type_uid == 20100202
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.time == fx.SYS_MS
    assert event.reg_value is not None
    assert (
        event.reg_value.path
        == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ExampleApp"
    )
    assert event.reg_value.name == "ExampleApp"
    assert event.reg_value.data == "C:\\Tools\\example.exe"
    assert event.actor is not None and event.actor.process is not None
    assert event.actor.process.pid == 4321
    assert event.unmapped["EventType"] == "INFO"
    assert "EventType: SetValue" in event.unmapped["Message"]
    _check_no_drop(
        fx.flat_sysmon_registry_value(),
        FLAT_ENVELOPE,
        {
            "TargetObject",
            "Details",
            "Image",
            "ProcessId",
            "AccountName",
            "Domain",
            "UtcTime",
        },
    )


def test_sysmon_14_maps_to_registry_rename() -> None:
    event = _normalize_record(fx.flat_sysmon_registry_rename())
    assert event.class_uid == 201001
    assert event.activity_id == 5
    assert event.metadata.log_name == SYSMON_CHANNEL
    assert event.reg_key is not None
    assert event.reg_key.path == "HKLM\\SOFTWARE\\ExampleCorp\\NewName"
    assert event.prev_reg_key is not None
    assert event.prev_reg_key.path == "HKLM\\SOFTWARE\\ExampleCorp\\OldName"
    assert event.unmapped["EventTypeOrignal"] == "INFO"
    _check_no_drop(
        fx.flat_sysmon_registry_rename(),
        FLAT_ENVELOPE,
        {
            "TargetObject",
            "NewName",
            "Image",
            "ProcessId",
            "AccountName",
            "Domain",
            "UtcTime",
        },
    )


def test_security_4697_maps_to_windows_service_activity() -> None:
    event = _normalize_record(fx.flat_security_service())
    assert event.class_uid == 201004
    assert event.category_uid == 1
    assert event.activity_id == 1
    assert event.type_uid == 20100401
    assert event.metadata.log_name == SECURITY_CHANNEL
    assert event.metadata.product.name == "Microsoft Windows"
    assert event.time == fx.SYS_MS
    assert event.win_service is not None
    assert event.win_service.name == "ExampleSupport"
    assert event.win_service.cmd_line == "C:\\Windows\\System32\\examplesup.exe"
    assert event.win_service.service_start_name == "LocalSystem"
    assert event.win_service.service_start_type_id == 3
    assert event.win_service.service_start_type == "Auto"
    assert event.win_service.service_type_id == 3
    assert event.win_service.service_type == "Own Process"
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "jdoe"
    assert event.actor.user.domain == "EXAMPLE"
    assert event.unmapped["ServiceStartType"] == "2"
    assert event.unmapped["ServiceType"] == "0x10"
    assert event.entity_keys.user == "example\\jdoe"
    _check_no_drop(
        fx.flat_security_service(),
        FLAT_ENVELOPE,
        {
            "ServiceName",
            "ServiceFileName",
            "ServiceAccount",
            "SubjectUserName",
            "SubjectDomainName",
            "TimeCreated",
        },
    )


def test_system_7045_maps_to_windows_service_activity() -> None:
    event = _normalize_record(fx.flat_service_install(channel="System"))
    assert event.class_uid == 201004
    assert event.activity_id == 1
    assert event.metadata.log_name == SYSTEM_CHANNEL
    assert event.win_service is not None
    assert event.win_service.name == "ExampleSupport"
    assert event.win_service.cmd_line == "C:\\Windows\\System32\\examplesup.exe"
    assert event.win_service.service_start_name is None
    assert event.win_service.service_start_type_id == 3
    assert event.win_service.service_start_type == "Auto"
    assert event.win_service.service_type_id == 99
    assert event.win_service.service_type == "user mode service"
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "jdoe"
    assert event.unmapped["StartType"] == "auto start"
    assert event.unmapped["ServiceType"] == "user mode service"
    _check_no_drop(
        fx.flat_service_install(channel="System"),
        FLAT_ENVELOPE,
        {"ServiceName", "ImagePath", "AccountName", "Domain", "TimeCreated"},
    )


def test_service_type_numbers_and_words() -> None:
    """SCM numbers (4697) and 7045 words share the OCSF id space."""
    record = fx.flat_security_service()
    record["ServiceStartType"] = "3"
    record["ServiceType"] = "0x1"
    event = _normalize_record(record)
    assert event.win_service is not None
    assert event.win_service.service_start_type_id == 4
    assert event.win_service.service_start_type == "Demand"
    assert event.win_service.service_type_id == 1
    assert event.win_service.service_type == "Kernel Driver"
    record["ServiceStartType"] = "9"
    record["ServiceType"] = "0xe0"
    event = _normalize_record(record)
    assert event.win_service is not None
    assert event.win_service.service_start_type_id == 99
    assert event.win_service.service_start_type == "9"
    assert event.win_service.service_type_id == 99
    assert event.win_service.service_type == "0xe0"
    install = fx.flat_service_install(channel="System")
    install["StartType"] = "demand start"
    install["ServiceType"] = "kernel mode driver"
    event = _normalize_record(install)
    assert event.win_service is not None
    assert event.win_service.service_start_type_id == 4
    assert event.win_service.service_type_id == 1


def test_sysmon_7_stays_unmapped_and_counted() -> None:
    """Sysmon 7 (image load) targets Module Activity: not mapped here."""
    with pytest.raises(UnmappedEvent) as excinfo:
        _normalize_record(fx.flat_unmapped(event_id=7, channel=SYSMON_CHANNEL))
    assert excinfo.value.key == (SYSMON_CHANNEL, 7)


def test_lowercase_security_unmapped_merges_with_security(tmp_path: Path) -> None:
    """WEF lowercase ``security`` counts in the canonical Security bucket."""
    lower = fx.flat_unmapped(channel="security")
    upper = fx.flat_unmapped(channel="Security")
    lines = [json.dumps(lower), json.dumps(upper)]
    archive = _write_zip(tmp_path / "svc.zip", {"events.json": lines})
    result = read_dataset_file(archive, dataset_rel="svc.zip")
    assert result.events == []
    assert result.unmapped == {(SECURITY_CHANNEL, 4688): 2}


def test_lowercase_channels_map_for_registry_and_service() -> None:
    """Case-insensitive channels keep the canonical log_name on new classes."""
    key = fx.flat_sysmon_registry_key()
    key["Channel"] = "microsoft-windows-sysmon/operational"
    event = _normalize_record(key)
    assert event.class_uid == 201001
    assert event.metadata.log_name == SYSMON_CHANNEL
    service = fx.flat_security_service()
    service["Channel"] = "security"
    event = _normalize_record(service)
    assert event.class_uid == 201004
    assert event.metadata.log_name == SECURITY_CHANNEL
    install = fx.flat_service_install(channel="System")
    install["Channel"] = "system"
    event = _normalize_record(install)
    assert event.class_uid == 201004
    assert event.metadata.log_name == SYSTEM_CHANNEL


def test_winlog_layout_maps_registry_and_service() -> None:
    """Newer nested winlog layout maps every new (channel, event id)."""
    cases = [
        (fx.winlog_sysmon_registry_key(), 201001, 1, SYSMON_CHANNEL),
        (fx.winlog_sysmon_registry_value(), 201002, 2, SYSMON_CHANNEL),
        (fx.winlog_sysmon_registry_rename(), 201001, 5, SYSMON_CHANNEL),
        (fx.winlog_security_service(), 201004, 1, SECURITY_CHANNEL),
        (fx.winlog_system_service(), 201004, 1, SYSTEM_CHANNEL),
    ]
    for record, class_uid, activity_id, channel in cases:
        event = _normalize_record(record)
        assert event.class_uid == class_uid
        assert event.activity_id == activity_id
        assert event.metadata.log_name == channel
        assert event.time == fx.SYS_MS
    key = _normalize_record(fx.winlog_sysmon_registry_key())
    assert key.reg_key is not None
    assert key.reg_key.path == "HKLM\\SOFTWARE\\ExampleCorp\\ExampleApp"
    value = _normalize_record(fx.winlog_sysmon_registry_value())
    assert value.reg_value is not None
    assert value.reg_value.name == "ExampleApp"
    assert value.reg_value.data == "C:\\Tools\\example.exe"
    rename = _normalize_record(fx.winlog_sysmon_registry_rename())
    assert rename.prev_reg_key is not None
    assert rename.prev_reg_key.path == "HKLM\\SOFTWARE\\ExampleCorp\\OldName"
    security = _normalize_record(fx.winlog_security_service())
    assert security.win_service is not None
    assert security.win_service.name == "ExampleSupport"
    assert security.win_service.service_start_type_id == 3
    system = _normalize_record(fx.winlog_system_service())
    assert system.win_service is not None
    assert system.win_service.service_start_type_id == 3
    assert "provider_name" in system.unmapped
