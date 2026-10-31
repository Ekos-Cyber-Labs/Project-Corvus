"""Registry-quality tests: files and paths are never pseudonym entities.

Dataset values are the public-dataset spellings named in the prompt
(``plink.exe`` and friends, ``pc01`` / ``pc01.example.corp``, the
``C:\\Users\\ieuser\\Desktop`` profile path). Backed by the shared
throwaway-Postgres guard; no paid API calls.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from corvus.guardrails.pseudonymizer import (
    Pseudonymizer,
    purge_file_pseudonyms,
    scan_entities,
)
from corvus.llm.agent import _incident_entities
from corvus.llm.tools import collect_incident_entities
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls

FILE_NAMES = [
    "plink.exe",
    "cmd.exe",
    "atbroker.exe",
    "tstheme.exe",
    "ui0detect.exe",
    "winlogon.exe",
]


@pytest.fixture
def registry_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield Pseudonymizer(test_url), test_url
    finally:
        _drop_database(admin_url, name)


def _rows(test_url: str) -> list[tuple[str, str, str]]:
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT entity_kind, entity_value, pseudonym FROM pseudonyms"
                " ORDER BY entity_kind, entity_value"
            )
            return [(str(a), str(b), str(c)) for a, b, c in cur.fetchall()]


def test_scan_never_finds_file_names() -> None:
    for name in FILE_NAMES:
        assert scan_entities(f"ran {name} now") == [], name
        assert scan_entities(f"ran C:\\Windows\\System32\\{name} now") == [], name
        assert scan_entities(f"ran /tmp/{name} now") == [], name


def test_scan_paths_give_no_host_or_domain() -> None:
    for text in (
        "ran C:\\Windows\\System32\\winlogon.exe now",
        "ran C:/Windows/System32/winlogon.exe now",
        "profile C:\\Users\\ieuser\\Desktop here",
        "profile /home/ieuser/Desktop here",
    ):
        hits = scan_entities(text)
        assert all(kind not in ("host", "domain") for kind, _ in hits), text
        assert all("Desktop" not in raw for _, raw in hits), text
        assert all("winlogon" not in raw for _, raw in hits), text


def test_scan_fqdn_needs_public_suffix() -> None:
    assert scan_entities("ping plink.exe") == []
    assert scan_entities("get a.sh") == []
    assert ("domain", "portal.example.org") in scan_entities(
        "beacon to https://portal.example.org/login"
    )
    assert ("ip", "198.51.100.7") in scan_entities("curl http://198.51.100.7/x")
    assert ("email", "carol@db01.example.com") in scan_entities(
        "mail carol@db01.example.com"
    )


def test_files_and_paths_reach_model_verbatim(registry_db: Any) -> None:
    pseudo, test_url = registry_db
    payload = {
        "host": "pc01",
        "process": {"name": "plink.exe", "cmd_line": "plink.exe 198.51.100.9"},
        "file": {"path": "C:\\Windows\\System32\\winlogon.exe"},
        "profile": "C:\\Users\\ieuser\\Desktop",
        "names": FILE_NAMES,
    }
    out = pseudo.pseudonymize(payload)
    assert out["host"].startswith("HOST-")
    assert out["process"]["name"] == "plink.exe"
    assert "plink.exe" in out["process"]["cmd_line"]
    assert "198.51.100.9" not in out["process"]["cmd_line"]
    assert out["file"]["path"] == "C:\\Windows\\System32\\winlogon.exe"
    assert out["names"] == FILE_NAMES
    rows = _rows(test_url)
    values = [value for _, value, _ in rows]
    for leaked_name in FILE_NAMES:
        assert leaked_name not in values
    assert all("\\" not in value and "/" not in value for value in values)
    assert all(
        not value.lower().endswith((".exe", ".dll", ".sys", ".sh")) for value in values
    )


def test_host_and_fqdn_unify_to_one_token(registry_db: Any) -> None:
    pseudo, test_url = registry_db
    out = pseudo.pseudonymize(
        {
            "host": "pc01",
            "hostname": "pc01.example.corp",
            "note": "on PC01 and pc01.example.corp and Pc01.Example.Corp.",
        }
    )
    token = out["host"]
    assert token.startswith("HOST-")
    assert out["hostname"] == token
    assert out["note"] == f"on {token} and {token} and {token}."
    rows = _rows(test_url)
    assert [(k, v) for k, v, _ in rows] == [("host", "pc01")]


def test_collect_entities_skips_files_and_paths() -> None:
    rows = [
        {
            "event_uid": "ev1",
            "time": 1,
            "class_uid": 1007,
            "host": "pc01",
            "user": "ieuser",
            "ip": None,
            "src_ip": None,
            "dst_ip": None,
            "data": {
                "device": {"hostname": "pc01.example.corp"},
                "actor": {"user": {"name": "ieuser"}},
                "process": {
                    "name": "plink.exe",
                    "cmd_line": "plink.exe -batch 198.51.100.9",
                    "file": {"path": "C:\\Windows\\System32\\winlogon.exe"},
                },
                "file": {"path": "C:\\Users\\ieuser\\Desktop\\notes.txt"},
            },
        }
    ]
    pairs = collect_incident_entities(rows)
    assert ("host", "pc01") in pairs
    assert ("ip", "198.51.100.9") in pairs
    for _, raw in pairs:
        assert not raw.lower().endswith(tuple(f".{e}" for e in ("exe", "txt", "sh")))
        assert "winlogon" not in raw
        assert "Desktop" not in raw
        assert "\\" not in raw


def test_triage_model_entities_must_match_typed(
    registry_db: Any, caplog: pytest.LogCaptureFixture
) -> None:
    items = [
        {
            "event_uid": "ev1",
            "time": 1,
            "class_uid": 1007,
            "host": "pc01",
            "user": "alice",
            "ip": None,
            "src_ip": "198.51.100.9",
            "dst_ip": None,
            "data": {
                "device": {"hostname": "pc01.example.corp"},
                "actor": {"user": {"name": "alice"}},
                "src_endpoint": {"ip": "198.51.100.9"},
            },
        }
    ]
    condensed = {
        "summary": "host ghost99 with plink.exe",
        "entities": [
            {"type": "host", "value": "pc01.example.corp"},
            {"type": "host", "value": "ghost99"},
            {"type": "user", "value": "alice"},
            {"type": "user", "value": "mallory"},
            {"type": "ip", "value": "198.51.100.9"},
            {"type": "ip", "value": "203.0.113.99"},
            {"type": "process", "value": "plink.exe"},
            {"type": "file", "value": "C:\\Windows\\System32\\winlogon.exe"},
            {"type": "domain", "value": "evil.example.net"},
        ],
    }
    with caplog.at_level(logging.INFO, logger="corvus.llm.agent"):
        pairs = _incident_entities(items, condensed)
    assert ("host", "pc01.example.corp") in pairs
    assert ("user", "alice") in pairs
    assert ("ip", "198.51.100.9") in pairs
    assert all(
        raw not in {r for _, r in pairs}
        for raw in (
            "ghost99",
            "mallory",
            "203.0.113.99",
            "plink.exe",
            "evil.example.net",
        )
    )
    assert all("winlogon" not in raw for _, raw in pairs)
    # Drops are counted, never valued, in the log.
    assert "ghost99" not in caplog.text
    assert "plink.exe" not in caplog.text
    assert "dropped" in caplog.text


def test_host_named_like_path_component_from_typed_field(registry_db: Any) -> None:
    pseudo, _ = registry_db
    out = pseudo.pseudonymize(
        {
            "host": "desktop",
            "file": {"path": "C:\\shares\\Desktop\\notes.txt"},
            "note": "desktop logged on",
        }
    )
    assert out["host"].startswith("HOST-")
    assert out["file"]["path"] == "C:\\shares\\Desktop\\notes.txt"
    assert out["note"] == f"{out['host']} logged on"


def test_user_named_like_file_stem_from_typed_field(registry_db: Any) -> None:
    pseudo, _ = registry_db
    out = pseudo.pseudonymize({"user": "plink", "note": "plink ran plink.exe"})
    assert out["user"].startswith("USER-")
    assert out["note"] == f"{out['user']} ran plink.exe"


def test_plink_in_command_line_left_ip_replaced(registry_db: Any) -> None:
    pseudo, _ = registry_db
    out = pseudo.pseudonymize(
        {"cmd_line": "PLINK.EXE -batch 198.51.100.9 && Plink.exe done"}
    )
    assert "198.51.100.9" not in out["cmd_line"]
    assert "PLINK.EXE" in out["cmd_line"]
    assert "Plink.exe" in out["cmd_line"]


def test_same_value_in_path_and_as_host(registry_db: Any) -> None:
    pseudo, _ = registry_db
    out = pseudo.pseudonymize(
        {
            "hostname": "pc01",
            "file": {"path": "C:\\shares\\pc01\\plink.exe"},
            "note": "pc01 shared",
        }
    )
    assert out["hostname"].startswith("HOST-")
    assert out["file"]["path"] == "C:\\shares\\pc01\\plink.exe"
    assert out["note"] == f"{out['hostname']} shared"


def test_mixed_case_file_and_host(registry_db: Any) -> None:
    pseudo, _ = registry_db
    out = pseudo.pseudonymize(
        {"host": "PC01", "note": "Pc01 ran PLINK.EXE on pC01.example.corp"}
    )
    token = out["host"]
    assert out["note"] == f"{token} ran PLINK.EXE on {token}"


def test_real_replay_events_register_no_files(registry_db: Any) -> None:
    replay = Path("data/replay/events")
    if not replay.is_dir():
        pytest.skip("replay store not available: data/replay/events missing")
    files = sorted(replay.glob("*.parquet"))
    if not files:
        pytest.skip("replay store not available: no parquet files")
    import pyarrow.parquet as pq

    rows: list[dict[str, Any]] = []
    for path in files[:2]:
        table = pq.read_table(
            path,
            columns=[
                "uid",
                "time",
                "class_uid",
                "host",
                "user",
                "ip",
                "src_ip",
                "dst_ip",
                "event_json",
            ],
        )
        for record in table.to_pylist()[:200]:
            rows.append(
                {
                    "event_uid": record["uid"],
                    "time": record["time"],
                    "class_uid": record["class_uid"],
                    "host": record["host"],
                    "user": record["user"],
                    "ip": record["ip"],
                    "src_ip": record["src_ip"],
                    "dst_ip": record["dst_ip"],
                    "data": json.loads(record["event_json"]),
                }
            )
    if not rows:
        pytest.skip("replay store not available: no events in first files")
    pseudo, test_url = registry_db
    pairs = collect_incident_entities(rows)
    pseudo.register(pairs)
    for kind, value, _ in _rows(test_url):
        if kind in ("host", "domain"):
            assert "\\" not in value and "/" not in value
            lowered = value.lower()
            assert not lowered.endswith(
                tuple(
                    f".{ext}"
                    for ext in (
                        "exe",
                        "dll",
                        "sys",
                        "bat",
                        "cmd",
                        "ps1",
                        "vbs",
                        "js",
                        "sh",
                        "txt",
                        "log",
                    )
                )
            ), value


def test_purge_keeps_referenced_wrong_rows(registry_db: Any) -> None:
    pseudo, test_url = registry_db
    assert pseudo.get_or_create("host", "pc01") is not None
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO pseudonyms (entity_kind, entity_value, pseudonym)"
                " VALUES ('domain', 'plink.exe', 'DOMAIN-9001'),"
                " ('domain', 'cmd.exe', 'DOMAIN-9002'),"
                " ('domain', 'pc01.example.corp', 'DOMAIN-9003')"
            )
            cur.execute(
                "INSERT INTO incidents (correlation_key, severity_floor, severity_id)"
                " VALUES ('corr-purge', 3, 3) RETURNING id"
            )
            row = cur.fetchone()
            assert row is not None
            incident_id = int(row[0])
            cur.execute(
                "INSERT INTO incident_analyses (incident_id, stage, status, payload)"
                " VALUES (%s, 'analysis', 'resolved', %s)",
                (incident_id, Jsonb({"note": "saw DOMAIN-9002"})),
            )
    dry = purge_file_pseudonyms(test_url)
    assert dry == {
        "candidates": 3,
        "referenced_kept": 1,
        "deleted": 0,
        "deletable": 2,
    }
    assert len(_rows(test_url)) == 4
    applied = purge_file_pseudonyms(test_url, apply=True)
    assert applied["deleted"] == 2
    remaining = {(kind, value) for kind, value, _ in _rows(test_url)}
    assert ("domain", "cmd.exe") in remaining
    assert ("domain", "plink.exe") not in remaining
    assert ("domain", "pc01.example.corp") not in remaining
    assert ("host", "pc01") in remaining
