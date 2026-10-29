"""Fixture-based tests for the Wazuh alert/archive mapper.

Every mapped decoder has a hand-written fixture under
``tests/fixtures/wazuh/`` following the documented Wazuh 4.x alert and
archive format (RFC 5737 IPs, ``example.com`` hosts only). Mapping
expectations here; OCSF conformance of the same fixtures lives in
``tests/test_conformance.py``.
"""

import json
from pathlib import Path

import pytest

from corvus.normalize import wazuh
from corvus.normalize.ocsf import (
    Authentication,
    DetectionFinding,
    FileSystemActivity,
    ProcessActivity,
)

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _map(name: str):
    return wazuh.map_alert(_load(name))


def test_sshd_failure_maps_to_authentication_failure() -> None:
    finding, event, key = _map("sshd_failure")
    assert key is None
    assert isinstance(event, Authentication)
    assert event.class_uid == 3002 and event.activity_id == 1
    assert event.status == "Failure" and event.status_id == 2
    assert event.user is not None and event.user.name == "deploy"
    assert event.src_endpoint is not None
    assert event.src_endpoint.ip == "198.51.100.23"
    assert event.src_endpoint.port == 4444
    assert event.device is not None and event.device.hostname == "web01"
    assert isinstance(finding, DetectionFinding)
    assert finding.severity_id == 3 and finding.severity == "Medium"
    assert finding.finding_info is not None
    assert finding.finding_info.analytic is not None
    assert finding.finding_info.analytic.uid == "5760"
    assert finding.finding_info.analytic.type_id == 1
    assert finding.finding_info.analytic.category == "syslog,sshd,authentication_failed"
    assert finding.finding_info.related_events is not None
    assert finding.evidences is not None and len(finding.evidences) == 1
    assert finding.evidences[0].uid == event.metadata.uid
    assert event.raw_data is not None and "5760" in event.raw_data


def test_sshd_success_maps_to_authentication_success() -> None:
    finding, event, key = _map("sshd_success")
    assert key is None
    assert isinstance(event, Authentication)
    assert event.status == "Success" and event.status_id == 1
    assert finding.severity_id == 2 and finding.severity == "Low"


def test_sudo_maps_to_process_activity_with_users_and_command() -> None:
    finding, event, key = _map("sudo")
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.class_uid == 1007 and event.activity_id == 1
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "deploy"
    assert event.process is not None
    assert event.process.cmd_line == "/usr/bin/systemctl restart nginx"
    assert event.process.name == "systemctl"
    assert event.process.user is not None and event.process.user.name == "root"
    assert event.unmapped.get("tty") == "pts/0"
    assert event.unmapped.get("pwd") == "/home/deploy"
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks or []
    assert [(a.technique.uid if a.technique else None) for a in attacks] == ["T1548"]
    assert attacks[0].sub_technique is not None
    assert attacks[0].sub_technique.uid == "T1548.003"


def test_auditd_syscall_maps_command_exe_and_users() -> None:
    finding, event, key = _map("auditd_syscall")
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.process is not None
    assert event.process.cmd_line == "touch /tmp/malicious_file"
    assert event.process.file is not None
    assert event.process.file.path == "/usr/bin/touch"
    assert event.process.pid == 4425
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "1001"
    assert "audit.key" in event.unmapped


def test_auditd_unset_auid_falls_back_to_uid() -> None:
    import copy

    hit = copy.deepcopy(_load("auditd_syscall"))
    hit["_source"]["data"]["audit"]["auid"] = "4294967295"
    finding, event, key = wazuh.map_alert(hit)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "0"


def test_auditd_cwd_counts_as_unmapped() -> None:
    finding, event, key = _map("auditd_cwd")
    assert isinstance(finding, DetectionFinding)
    assert event is None
    assert key == ("auditd", "80790")


def test_syscheck_integrity_changed_maps_to_file_activity_update() -> None:
    finding, event, key = _map("syscheck_integrity_changed")
    assert key is None
    assert isinstance(event, FileSystemActivity)
    assert event.class_uid == 1001 and event.activity_id == 3
    assert event.file is not None and event.file.path == "/etc/cron.d/evil"
    assert event.file.hashes is not None
    by_algorithm = {fp.algorithm_id: fp.value for fp in event.file.hashes}
    assert by_algorithm[1] == "d41d8cd98f00b204e9800998ecf8427e"
    assert by_algorithm[3] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert finding.severity_id == 3
    assert event.metadata.log_name == "syscheck_integrity_changed"


def test_unknown_decoder_still_emits_finding_and_counts() -> None:
    finding, event, key = _map("unknown_decoder")
    assert isinstance(finding, DetectionFinding)
    assert finding.severity_id == 4 and finding.severity == "High"
    assert finding.evidences is None
    assert event is None
    assert key == ("nginx-access", "100002")


def test_archive_maps_to_event_without_finding() -> None:
    hit = _load("archive_sshd")
    event, key = wazuh.map_archive(hit)
    assert key is None
    assert isinstance(event, Authentication)
    assert event.status == "Failure"
    assert event.metadata.uid == hit["_id"]
    assert event.unmapped.get("wazuh_id") == "1714651560.20001"


def test_archive_without_doc_id_counts_as_unknown() -> None:
    import copy

    hit = copy.deepcopy(_load("archive_sshd"))
    del hit["_id"]
    event, key = wazuh.map_archive(hit)
    assert event is None
    assert key == ("unknown", None)


def test_sshd_without_user_counts_as_unmapped() -> None:
    hit = _load("sshd_failure")
    del hit["_source"]["data"]["srcuser"]
    hit["_source"]["full_log"] = (
        "May  2 12:06:00 web01 sshd[10040]: pam_unix(sshd:auth): authentication failure"
    )
    finding, event, key = wazuh.map_alert(hit)
    assert isinstance(finding, DetectionFinding)
    assert event is None
    assert key == ("sshd", "5760")


def test_map_alert_rejects_hits_without_rule_or_id() -> None:
    hit = _load("archive_sshd")
    with pytest.raises(ValueError, match="rule"):
        wazuh.map_alert(hit)
    hit = _load("sshd_failure")
    del hit["_source"]["id"]
    with pytest.raises(ValueError, match="id"):
        wazuh.map_alert(hit)


@pytest.mark.parametrize(
    ("level", "severity_id", "severity"),
    [
        (0, 2, "Low"),
        (1, 2, "Low"),
        (3, 2, "Low"),
        (4, 3, "Medium"),
        (7, 3, "Medium"),
        (8, 4, "High"),
        (11, 4, "High"),
        (12, 5, "Critical"),
        (15, 5, "Critical"),
        (99, 5, "Critical"),
    ],
)
def test_severity_mapping(level: int, severity_id: int, severity: str) -> None:
    assert wazuh.severity_for_level(level) == (severity_id, severity)


@pytest.mark.parametrize(
    ("value", "expected_ms"),
    [
        ("2024-05-02T12:00:00.048+0000", 1714651200048),
        ("2024-05-02T12:00:00.048+00:00", 1714651200048),
        ("2024-05-02T12:00:00.048Z", 1714651200048),
        ("2024-05-02T12:00:00+0000", 1714651200000),
        (1714651200048, 1714651200048),
    ],
)
def test_parse_wazuh_time(value: object, expected_ms: int) -> None:
    assert wazuh.parse_wazuh_time(value) == expected_ms  # type: ignore[arg-type]


def test_parse_wazuh_time_rejects_garbage() -> None:
    for bad in ("not-a-time", "", None, True, "2017 Jan 05 14:11:21"):
        with pytest.raises(ValueError):
            wazuh.parse_wazuh_time(bad)  # type: ignore[arg-type]
