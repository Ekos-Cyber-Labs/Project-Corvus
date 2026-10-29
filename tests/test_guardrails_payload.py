"""Tests for model-bound payload preparation.

Masking always runs on the structured payload; ``visible`` wraps
detector labels under ``detector_labels`` while ``blind`` strips the
technique-bearing ones; cloud trust adds pseudonyms and secret
redaction while on-prem trust skips both.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from corvus.guardrails.payload import PreparedPayload, prepare_payload
from corvus.llm.config import BackendConfig
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def pg_url() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _destination(trust: str) -> BackendConfig:
    return BackendConfig(
        purpose="analysis",
        model="muse-spark-1.3",
        base_url="https://models.example.net/v1",
        trust=trust,  # type: ignore[arg-type]
        concurrency=4,
        requests_per_minute=30,
        max_input_tokens=65536,
        max_output_tokens=6000,
        api_key="TEST-API-KEY-VALUE-7",
    )


def _incident() -> dict[str, Any]:
    return {
        "incident_id": 7,
        "severity_floor": 3,
        "findings": [
            {
                "class_uid": 2004,
                "finding_info": {
                    "uid": "finding-1",
                    "title": "Suspicious PowerShell Download",
                    "analytic": {
                        "name": "Suspicious PowerShell Download",
                        "uid": "rule-1",
                        "type_id": 1,
                    },
                    "attacks": [
                        {
                            "tactic": {"uid": "TA0002", "name": "Execution"},
                            "technique": {"uid": "T1059.001", "name": "PowerShell"},
                            "version": "v20.0",
                        }
                    ],
                    "related_events": [{"uid": "evt-1"}],
                    "src_url": "https://example.com/rules/1",
                    "unmapped": {
                        "sigma_author": "Example Author",
                        "tags": ["attack.t1059.001", "attack.execution"],
                    },
                },
                "evidences": [
                    {
                        "uid": "evt-1",
                        "device": {
                            "hostname": "WEB01.example.com",
                            "ip": "192.0.2.10",
                        },
                        "actor": {"user": {"name": "admin"}},
                        "process": {
                            "cmd_line": (
                                "powershell -enc T1059 technique_name=PowerShell"
                            )
                        },
                        "extra_args": "deploy --password s3cretPassw0rd now",
                    }
                ],
            }
        ],
    }


def test_visible_wraps_labels_and_masks(pg_url: str) -> None:
    prepared = prepare_payload(_incident(), _destination("onprem"), "visible")
    assert isinstance(prepared, PreparedPayload)
    assert prepared.labels_mode == "visible"
    info = prepared.payload["findings"][0]["finding_info"]
    assert info["title"] == "Suspicious PowerShell Download"
    labels = info["detector_labels"]
    assert labels["attacks"][0]["technique"]["uid"] == "[TECHNIQUE-ID]"
    assert labels["analytic"]["name"] == "Suspicious PowerShell Download"
    assert labels["tags"] == {"tags": ["attack.[TECHNIQUE-ID]", "attack.execution"]}
    assert "attacks" not in info
    assert "analytic" not in info
    cmdline = prepared.payload["findings"][0]["evidences"][0]["process"]["cmd_line"]
    assert "T1059" not in cmdline
    assert "technique_name=[TECHNIQUE-NAME]" in cmdline


def test_blind_strips_technique_labels(pg_url: str) -> None:
    prepared = prepare_payload(_incident(), _destination("onprem"), "blind")
    assert prepared.labels_mode == "blind"
    dumped = json.dumps(prepared.payload)
    assert "T1059" not in dumped
    assert "PowerShell" not in dumped.replace("Suspicious PowerShell Download", "")
    assert "attacks" not in dumped
    info = prepared.payload["findings"][0]["finding_info"]
    assert info["title"] == "Suspicious PowerShell Download"
    assert info["analytic"]["name"] == "Suspicious PowerShell Download"
    assert "tags" not in json.dumps(info.get("unmapped", {}))


def test_rule_titles_untouched_in_both_modes(pg_url: str) -> None:
    for mode in ("visible", "blind"):
        prepared = prepare_payload(_incident(), _destination("onprem"), mode)
        info = prepared.payload["findings"][0]["finding_info"]
        assert info["title"] == "Suspicious PowerShell Download"


def test_env_selects_default_mode(pg_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DETECTOR_LABELS", "blind")
    prepared = prepare_payload(_incident(), _destination("onprem"))
    assert prepared.labels_mode == "blind"
    monkeypatch.delenv("DETECTOR_LABELS")
    prepared = prepare_payload(_incident(), _destination("onprem"))
    assert prepared.labels_mode == "visible"


def test_invalid_modes_rejected(pg_url: str) -> None:
    with pytest.raises(ValueError):
        prepare_payload(_incident(), _destination("onprem"), "obscured")
    with pytest.raises(ValueError):
        prepare_payload(_incident(), _destination("onprem"), 42)  # type: ignore[arg-type]


def test_invalid_trust_rejected(pg_url: str) -> None:
    with pytest.raises(ValueError):
        prepare_payload(_incident(), _destination("datacenter"), "visible")
    with pytest.raises(ValueError):
        prepare_payload(_incident(), object(), "visible")


def test_onprem_skips_pseudonyms_and_redaction(pg_url: str) -> None:
    prepared = prepare_payload(_incident(), _destination("onprem"), "visible")
    dumped = json.dumps(prepared.payload)
    assert "WEB01.example.com" in dumped
    assert "192.0.2.10" in dumped
    assert "s3cretPassw0rd" in dumped


def test_cloud_pseudonymizes_and_redacts(pg_url: str) -> None:
    prepared = prepare_payload(
        _incident(), _destination("cloud"), "visible", database_url=pg_url
    )
    assert prepared.labels_mode == "visible"
    dumped = json.dumps(prepared.payload)
    assert "WEB01.example.com" not in dumped
    assert "web01" not in dumped.lower().replace("host-0001", "")
    assert "192.0.2.10" not in dumped
    assert "s3cretPassw0rd" not in dumped
    assert "HOST-0001" in dumped
    assert "IP-0001" in dumped
    assert "[REDACTED:credential]" in dumped


def test_cloud_without_store_refuses(
    pg_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError):
        prepare_payload(_incident(), _destination("cloud"), "visible")


def _typed_event() -> dict[str, Any]:
    """Event A: jump01/frank appear here as typed entities."""
    return {
        "class_uid": 3002,
        "category_uid": 1,
        "activity_id": 1,
        "time": 1714656100000,
        "severity_id": 2,
        "metadata": {"product": {"name": "wazuh"}, "uid": "evt-typed-1"},
        "device": {"hostname": "jump01"},
        "actor": {"user": {"name": "frank"}},
    }


def _leaky_event() -> dict[str, Any]:
    """Event B: entities live only in cmd_line, raw_data and unmapped."""
    return {
        "class_uid": 1007,
        "category_uid": 1,
        "activity_id": 1,
        "time": 1714656180000,
        "severity_id": 3,
        "metadata": {"product": {"name": "wazuh"}, "uid": "evt-leak-1"},
        "device": {"hostname": "WORKSTATION01", "ip": "192.0.2.99"},
        "actor": {"user": {"name": "operator", "domain": "corp"}},
        "process": {
            "pid": 1234,
            "name": "curl.exe",
            "cmd_line": (
                "curl http://198.51.100.7/a.sh -o C:\\Users\\bob\\a.sh"
                " && scp a.sh carol@db01.example.com:/tmp"
                " ; ping 203.0.113.9"
                " ; nslookup intranet.corp.example.com"
            ),
        },
        "raw_data": json.dumps(
            {
                "Agent": {"name": "filesrv02"},
                "TargetUserName": "alice",
                "CommandLine": "net user dave /add",
                "Message": "Logon by erin from 198.51.100.77 on FILESRV02",
            }
        ),
        "unmapped": {"note": "seen from jump host jump01 by frank"},
    }


def test_cloud_drops_raw_data(pg_url: str) -> None:
    assert "raw_data" in _leaky_event()
    prepared = prepare_payload(
        {"events": [_leaky_event()]},
        _destination("cloud"),
        "visible",
        database_url=pg_url,
    )
    assert "raw_data" not in json.dumps(prepared.payload)
    kept = prepare_payload(
        {"events": [_leaky_event()]}, _destination("onprem"), "visible"
    )
    assert "raw_data" in json.dumps(kept.payload)


def test_cloud_free_text_acceptance(pg_url: str) -> None:
    # The review lists 14 strings but says 17; the extra three are the
    # full FQDN forms plus "intranet", all covered by the same spans.
    leaked = [
        "alice",
        "example.com",
        "198.51.100.7",
        "203.0.113.9",
        "bob",
        "carol",
        "db01",
        "db01.example.com",
        "intranet.corp",
        "intranet.corp.example.com",
        "intranet",
        "dave",
        "erin",
        "198.51.100.77",
        "filesrv02",
        "jump01",
        "frank",
    ]
    assert len(leaked) == 17
    incident = {"incident_id": 9, "events": [_typed_event(), _leaky_event()]}
    prepared = prepare_payload(
        incident,
        _destination("cloud"),
        "visible",
        database_url=pg_url,
        entities=[("host", "jump01"), ("user", "frank")],
    )
    dumped = json.dumps(prepared.payload).lower()
    for secret in leaked:
        assert secret not in dumped, secret


def test_cloud_ten_more_free_text_events(pg_url: str) -> None:
    cases: list[tuple[dict[str, Any], list[tuple[str, str]] | None, list[str]]] = [
        (
            {"cmd_line": "net user backup_admin /add && ping 203.0.113.21"},
            None,
            ["backup_admin", "203.0.113.21"],
        ),
        (
            {
                "unmapped": {
                    "contact": "noc@example.net",
                    "elevate": "runas /user:corp\\svc_deploy",
                }
            },
            None,
            ["noc@example.net", "corp\\svc_deploy", "svc_deploy", "corp"],
        ),
        (
            {
                "reg_key": "HKLM\\Software\\Vendor",
                "value_name": "Server",
                "value_data": "filesrv07.corp.example.com",
            },
            None,
            ["filesrv07.corp.example.com", "filesrv07"],
        ),
        (
            {"file_path": "\\\\nas02\\backups\\img.vhd"},
            None,
            ["nas02"],
        ),
        (
            {"message": "beacon to https://portal.example.org/login?next=/dash"},
            None,
            ["portal.example.org", "portal"],
        ),
        (
            {"message": "solicited-router-advertisement from 2001:db8::77"},
            None,
            ["2001:db8::77"],
        ),
        (
            {
                "events": [
                    {"cmd_line": "setup /user:deploy_bot /quiet"},
                    {"message": "key in /home/deploy_bot/.ssh/authorized_keys"},
                ]
            },
            None,
            ["deploy_bot"],
        ),
        (
            {"message": "EAST\\jrivera logged on from 198.51.100.88"},
            None,
            ["east\\jrivera", "jrivera", "198.51.100.88"],
        ),
        (
            {
                "cmd_line": "ssh -u deploy_key deploy@web09.example.com",
                "unmapped": {"note": "key approved for keymaster"},
            },
            [("user", "keymaster")],
            [
                "deploy_key",
                "deploy@web09.example.com",
                "web09",
                "deploy",
                "keymaster",
            ],
        ),
        (
            {
                "file": "C:\\Users\\svc_sql\\data.mdf",
                "cmd_line": "net use \\\\db03\\sql /user:corp\\sqlsvc S3cretWord",
            },
            None,
            ["svc_sql", "db03", "corp\\sqlsvc", "sqlsvc", "s3cretword"],
        ),
    ]
    assert len(cases) == 10
    for payload, entities, absent in cases:
        prepared = prepare_payload(
            payload,
            _destination("cloud"),
            "visible",
            database_url=pg_url,
            entities=entities,
        )
        dumped = json.dumps(prepared.payload).lower()
        for secret in absent:
            assert secret.lower() not in dumped, (secret, dumped)


def test_entities_ignored_onprem(pg_url: str) -> None:
    prepared = prepare_payload(
        {"note": "seen on jump01"},
        _destination("onprem"),
        "visible",
        entities=[("host", "jump01")],
    )
    assert "jump01" in json.dumps(prepared.payload)
