"""OCSF conformance: every emitted record matches the pinned schema.

Runs ``corvus/normalize/conformance.py`` over the output of every
normalizer fixture (Windows layouts, the SIEM fixtures, Detection
Findings built by the Sigma engine) and over a sample of real replay
records per class when the replay store exists. Missing schema files
fail with the fetch command; nothing skips. No allowlist, no xfail:
a non-conformant mapper is fixed, not excused.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from corvus.adapters.replay.findings import write_findings
from corvus.adapters.replay.loader import load_path
from corvus.adapters.replay.schema import (
    event_to_row,
    finding_to_row,
    findings_dir,
    serialize_ocsf,
)
from corvus.attack.dictionary import AttackDictionary
from corvus.detect.engine import evaluate
from corvus.detect.findings import build_finding, finding_uid
from corvus.detect.rules import CompiledRule, load_rules
from corvus.normalize import conformance as conf
from corvus.normalize.conformance import ConformanceError, check_record
from corvus.normalize.ocsf import OcsfEvent
from corvus.normalize.windows import (
    UnmappedEvent,
    extract_evtx_parts,
    extract_json_parts,
    make_uid,
    normalize_event,
    sanitize_record,
)
from tests.fixtures import siem_events
from tests.fixtures import windows_events as fx

UID_BASE = "conformance-fixture"


def _stored(event: OcsfEvent) -> dict[str, Any]:
    """Parse exactly what the shared store serializer emits."""
    return json.loads(serialize_ocsf(event))


def _check(event: OcsfEvent) -> None:
    errors = check_record(_stored(event))
    assert errors == [], "\n".join(errors)


def _normalize_record(record: dict[str, Any], lineno: int = 1) -> OcsfEvent:
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, lineno
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid(UID_BASE, record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )


def _normalize_evtx(record: dict[str, Any]) -> OcsfEvent:
    channel, event_id, record_id, fields, computer, raw_time = extract_evtx_parts(
        record
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid(UID_BASE, record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record["Event"]),
    )


def _windows_records() -> list[tuple[str, dict[str, Any]]]:
    """Every mapped Windows fixture record (flat, old-beat, winlog)."""
    key_variants = ["CreateKey", "DeleteKey", "DeleteValue", "SetValue", "RenameKey"]
    records: list[tuple[str, dict[str, Any]]] = [
        ("sysmon-1", fx.flat_sysmon_process()),
        ("sysmon-1-minimal", fx.flat_minimal_process()),
        ("sysmon-1-unicode", fx.flat_unicode_process()),
        ("sysmon-3", fx.flat_sysmon_network()),
        ("sysmon-7", fx.flat_sysmon_module()),
        ("sysmon-7-winlog", fx.winlog_sysmon_module()),
        ("sysmon-10", fx.flat_sysmon_access()),
        ("sysmon-11", fx.flat_sysmon_file()),
        ("sysmon-13", fx.flat_sysmon_registry_value()),
        ("sysmon-14", fx.flat_sysmon_registry_rename()),
        ("security-4624", fx.flat_security_logon(success=True)),
        ("security-4625", fx.flat_security_logon(success=False)),
        ("security-4698", fx.flat_security_task()),
        ("security-4698-xml", fx.flat_security_task_xml()),
        ("security-4697", fx.flat_security_service()),
        ("system-7045", fx.flat_service_install(channel="System")),
        ("taskscheduler-106", fx.flat_taskscheduler_106()),
        ("ps-4104", fx.flat_powershell_script()),
        ("ps-4104-message", fx.flat_powershell_script_message()),
        ("ps-4103", fx.flat_powershell_module()),
        ("ps-4103-message", fx.flat_powershell_module_message()),
        ("ps-800", fx.flat_windows_powershell_pipeline()),
        ("ps-800-data", fx.flat_windows_powershell_pipeline_data()),
        ("security-lowercase", fx.flat_lowercase_channel_logon()),
        ("old-beat-network", fx.old_beat_sysmon_network()),
        ("old-beat-logon", fx.old_beat_security_logon()),
        ("winlog-file", fx.winlog_sysmon_file()),
        ("winlog-reg-key", fx.winlog_sysmon_registry_key()),
        ("winlog-reg-value", fx.winlog_sysmon_registry_value()),
        ("winlog-reg-rename", fx.winlog_sysmon_registry_rename()),
        ("winlog-service", fx.winlog_security_service()),
        ("winlog-system", fx.winlog_system_service()),
    ]
    for variant in key_variants:
        records.append(
            (f"sysmon-12-{variant}", fx.flat_sysmon_registry_key(event_type=variant))
        )
    for part in fx.flat_powershell_script_split():
        records.append(("ps-4104-split", part))
    filler = fx.flat_sysmon_registry_key()
    filler["Message"] = "Registry object added or deleted:\r\nRuleName: -\r\n"
    records.append(("sysmon-12-filler", filler))
    return records


def test_windows_fixtures_conform() -> None:
    for name, record in _windows_records():
        try:
            event = _normalize_record(record)
        except UnmappedEvent as exc:
            pytest.fail(f"{name}: unexpectedly unmapped ({exc.key})")
        errors = check_record(_stored(event))
        assert errors == [], f"{name}:\n" + "\n".join(errors)


def test_evtx_fixture_conforms() -> None:
    _check(_normalize_evtx(fx.evtx_sysmon_process()))


def test_unmapped_fixtures_stay_unmapped() -> None:
    """Unmapped layouts raise instead of emitting non-conformant events."""
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_unmapped())
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_windows_powershell_provider())
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_powershell_module_empty())
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_windows_powershell_pipeline_empty())
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_sysmon_file_no_target())
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_sysmon_registry_value_no_target())
    with pytest.raises(UnmappedEvent):
        _normalize_record(fx.flat_security_service_no_name())
    with pytest.raises(UnmappedEvent):
        _normalize_evtx(fx.evtx_rpc_no_channel())


def test_siem_fixtures_conform() -> None:
    for event in siem_events.make_siem_fixture_events():
        errors = check_record(_stored(event))
        assert errors == [], "\n".join(errors)


def test_wazuh_fixtures_conform() -> None:
    """Every Wazuh-mapped record (finding, event, archive) conforms."""
    import json as jsonlib

    from corvus.normalize import wazuh as wazuh_mapper

    fixture_dir = Path(__file__).parent / "fixtures" / "wazuh"
    for name in sorted(path.name for path in fixture_dir.glob("*.json")):
        hit = jsonlib.loads((fixture_dir / name).read_text(encoding="utf-8"))
        if "wazuh-archives" in hit.get("_index", ""):
            event, key = wazuh_mapper.map_archive(hit)
            assert key is None, f"{name}: unexpectedly unmapped ({key})"
            assert event is not None, f"{name}: no event mapped"
            errors = check_record(_stored(event))
            assert errors == [], f"{name}:\n" + "\n".join(errors)
            continue
        finding, event, _key = wazuh_mapper.map_alert(hit)
        errors = check_record(_stored(finding))
        assert errors == [], f"{name} finding:\n" + "\n".join(errors)
        if event is not None:
            errors = check_record(_stored(event))
            assert errors == [], f"{name} event:\n" + "\n".join(errors)


def _attack() -> AttackDictionary:
    return AttackDictionary.from_compact(
        {
            "tactics": {"execution": {"name": "Execution", "id": "TA0002"}},
            "tactic_order": ["execution"],
            "techniques": {
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "tactics": ["execution"],
                    "is_subtechnique": False,
                    "parent": None,
                    "deprecated": False,
                    "revoked": False,
                    "revoked_by": None,
                },
                "T1059.001": {
                    "name": "PowerShell",
                    "tactics": ["execution"],
                    "is_subtechnique": True,
                    "parent": "T1059",
                    "deprecated": False,
                    "revoked": False,
                    "revoked_by": None,
                },
            },
        }
    )


def _compiled_rule() -> CompiledRule:
    return CompiledRule(
        rule_id="11111111-1111-4111-8111-111111111111",
        title="Probe rule",
        description="Probe description.",
        author="Probe Author",
        level="high",
        tags=[("attack", "t1059.001"), ("attack", "execution")],
        references=[],
        group="process_creation",
        sql="SELECT * FROM slice WHERE 1 = 1",
        source_file="proc/rule.yml",
        rel_path="process_creation/rule.yml",
    )


def test_sigma_finding_conforms() -> None:
    """A Detection Finding built by the Sigma engine validates clean."""
    from corvus.detect.engine import MatchedEvent

    matched = MatchedEvent(
        uid="event-uid-1",
        time=fx.SYS_MS,
        class_uid=1007,
        activity_id=1,
        host="web01",
        device={"hostname": "web01.example.com", "type": "Unknown", "type_id": 0},
        actor={"user": {"name": "jdoe", "domain": "EXAMPLE"}},
        process={"pid": 1234, "name": "powershell.exe"},
        file={
            "path": "C:\\Windows\\powershell.exe",
            "type": "Executable File",
            "type_id": 8,
        },
        src_endpoint=None,
        dst_endpoint=None,
    )
    finding = build_finding(_compiled_rule(), matched, _attack(), "20.0")
    assert finding.finding_info is not None
    assert finding.finding_info.uid == finding.metadata.uid
    assert finding.metadata.uid == finding_uid(
        "11111111-1111-4111-8111-111111111111", "event-uid-1"
    )
    _check(finding)


def test_sigma_engine_findings_conform(tmp_path: Path) -> None:
    """End to end: rule match over a fixture store yields clean findings."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    archive = data_dir / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "events.json",
            json.dumps(fx.flat_sysmon_process()) + "\n",
        )
    replay_dir = tmp_path / "replay"
    summary = load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.events_total == 1
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "probe.yml").write_text(
        "title: Probe conformance\n"
        "id: 22222222-2222-4222-8222-222222222222\n"
        "status: test\n"
        "description: Probe rule.\n"
        "author: Probe Author\n"
        "logsource:\n"
        "  product: windows\n"
        "  category: process_creation\n"
        "detection:\n"
        "  selection:\n"
        "    Image|contains: 'powershell'\n"
        "  condition: selection\n"
        "level: high\n",
        encoding="utf-8",
    )
    compiled, _ = load_rules(rules_dir)
    assert len(compiled) == 1
    matches, infos, _ = evaluate(replay_dir, compiled)
    assert compiled[0].rule_id in matches
    stats = write_findings(replay_dir, compiled, matches, infos, _attack(), "20.0")
    assert stats.findings == 1
    checked = 0
    for path in sorted(findings_dir(replay_dir).glob("*.parquet")):
        import pyarrow.parquet as pq

        for row in pq.read_table(path).to_pylist():
            record = json.loads(row["finding_json"])
            assert "entity_keys" not in record
            errors = check_record(record)
            assert errors == [], "\n".join(errors)
            checked += 1
    assert checked == 1


def _assert_no_nones(value: Any, path: str = "event") -> None:
    """Fail on any None in serialized output: nulls must be omitted."""
    if value is None:
        pytest.fail(f"{path} is null in stored output")
    if isinstance(value, dict):
        for name, item in value.items():
            _assert_no_nones(item, f"{path}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_nones(item, f"{path}[{index}]")


def test_serializer_omits_nulls_and_entity_keys() -> None:
    """The shared serializer drops every None, so null names cannot hide."""
    for event in siem_events.make_siem_fixture_events():
        record = json.loads(serialize_ocsf(event))
        assert "entity_keys" not in record
        _assert_no_nones(record)
    for name, raw in _windows_records():
        record = json.loads(serialize_ocsf(_normalize_record(raw)))
        assert "entity_keys" not in record, name
        _assert_no_nones(record, name)


def test_store_rows_exclude_entity_keys() -> None:
    """The serialized store rows carry keys as columns, never as OCSF."""
    event = _normalize_record(fx.flat_sysmon_process())
    row = event_to_row(event)
    assert "entity_keys" not in json.loads(row["event_json"])
    assert check_record(json.loads(row["event_json"])) == []
    matched_rule = _compiled_rule()
    from corvus.detect.engine import MatchedEvent

    finding = build_finding(
        matched_rule,
        MatchedEvent(
            uid="event-uid-1",
            time=fx.SYS_MS,
            class_uid=1007,
            activity_id=1,
            host="web01",
            device={"hostname": "web01.example.com", "type": "Unknown", "type_id": 0},
            actor=None,
            process=None,
            file=None,
            src_endpoint=None,
            dst_endpoint=None,
        ),
        _attack(),
        "20.0",
    )
    finding_row = finding_to_row(finding, matched_rule.rule_id, matched_rule.level)
    assert "entity_keys" not in json.loads(finding_row["finding_json"])
    assert check_record(json.loads(finding_row["finding_json"])) == []


def test_replay_sample_conforms() -> None:
    """A deterministic per-class sample of real replay records validates clean.

    Two passes over the sorted event files: first count rows per class,
    then check every Nth row of each class (stride ``count // 25``), so
    the sample spreads across all files instead of clustering in the
    first ones. Checks the stored bytes exactly as written.
    """

    store = Path("data/replay") / "events"
    if not store.is_dir():
        pytest.skip("no replay store; run `corvus replay load data` first")
    files = sorted(store.glob("*.parquet"))
    if not files:
        pytest.skip("replay store has no event files")
    import pyarrow.parquet as pq

    counts: dict[int, int] = {}
    for path in files:
        for row in pq.read_table(path, columns=["class_uid"]).to_pylist():
            counts[row["class_uid"]] = counts.get(row["class_uid"], 0) + 1
    assert counts, "replay store is empty"
    strides = {uid: max(1, n // 25) for uid, n in counts.items()}
    seen: dict[int, int] = {}
    checked: dict[int, int] = {}
    for path in files:
        table = pq.read_table(path, columns=["class_uid", "event_json"])
        for row in table.to_pylist():
            class_uid = row["class_uid"]
            index = seen.get(class_uid, 0)
            seen[class_uid] = index + 1
            if index % strides[class_uid] != 0:
                continue
            record = json.loads(row["event_json"])
            errors = check_record(record)
            assert errors == [], f"class {class_uid}:\n" + "\n".join(errors)
            checked[class_uid] = checked.get(class_uid, 0) + 1
    assert checked, "replay store is empty"
    assert set(checked) == set(counts), (
        f"sample missed classes: {sorted(set(counts) - set(checked))}"
    )


def test_missing_schema_files_fail_with_fetch_command(tmp_path: Path) -> None:
    with pytest.raises(ConformanceError, match=r"scripts/fetch_datasets\.py"):
        conf._Schema(tmp_path / "absent")
    with pytest.raises(ConformanceError, match=r"scripts/fetch_datasets\.py"):
        conf._Schema(tmp_path)


def test_unknown_class_uid_fails() -> None:
    assert check_record({"class_uid": 999999}) == ["event: unknown class_uid 999999"]


def _valid_process_record() -> dict[str, Any]:
    return _stored(_normalize_record(fx.flat_sysmon_process()))


def test_missing_required_attribute_fails_precisely() -> None:
    record = _valid_process_record()
    del record["process"]
    assert check_record(record) == [
        "event.process: required attribute of class 1007 is missing or null"
    ]


def test_unknown_attribute_fails_precisely() -> None:
    record = _valid_process_record()
    record["no_such_attr"] = 1
    assert check_record(record) == [
        "event.no_such_attr: unknown attribute for class 1007 "
        "(not in the pinned schema)"
    ]


def test_unknown_null_attribute_fails_precisely() -> None:
    record = _valid_process_record()
    record["no_such_attr"] = None
    assert check_record(record) == [
        "event.no_such_attr: unknown attribute for class 1007 "
        "(not in the pinned schema)"
    ]


def test_invalid_enum_id_fails_precisely() -> None:
    record = _stored(_normalize_record(fx.flat_sysmon_network()))
    record["severity_id"] = 7
    (message,) = check_record(record)
    assert message.startswith(
        "event.severity_id: 7 is not a listed severity_id enum value"
    )
    assert "[0, 1, 2, 3, 4, 5, 6, 99]" in message


def test_integer_where_string_required_fails_precisely() -> None:
    record = _valid_process_record()
    assert isinstance(record["metadata"], dict)
    record["metadata"]["uid"] = 123
    assert check_record(record) == ["event.metadata.uid: expected a string, got int"]


def test_broken_nested_record_fails_precisely() -> None:
    record = _valid_process_record()
    assert isinstance(record["device"], dict)
    record["device"]["type_id"] = "Unknown"
    assert check_record(record) == [
        "event.device.type_id: expected an integer, got str"
    ]
    record2 = _valid_process_record()
    assert isinstance(record2["process"], dict)
    assert isinstance(record2["process"]["file"], dict)
    del record2["process"]["file"]["name"]
    assert check_record(record2) == [
        "event.process.file.name: required attribute of file is missing"
    ]
