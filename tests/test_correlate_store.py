"""Incident storage integration tests (always run; never skip).

Covers migration ``0003_severity_factors.sql`` (applies twice
cleanly) and the idempotent incident upsert: re-running the store
over the same incidents leaves the same rows.
"""

from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from corvus.attack import AttackDictionary
from corvus.correlate import correlate_findings
from corvus.state.incidents import (
    ms_to_timestamptz,
    stored_incident_count,
    upsert_incidents,
)
from corvus.state.migrate import MIGRATIONS_DIR, migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls
from tests.test_correlate import make_auth, make_finding

_COMPACT: dict[str, object] = {
    "tactics": {
        "discovery": {"name": "Discovery", "id": "TA0007"},
        "execution": {"name": "Execution", "id": "TA0002"},
    },
    "tactic_order": ["discovery", "execution"],
    "techniques": {
        "T1083": {
            "name": "File and Directory Discovery",
            "tactics": ["discovery"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactics": ["execution"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
    },
}

_COLUMNS = (
    "correlation_key, title, entity_keys, techniques, event_uids, "
    "first_seen, last_seen, deterministic_score, severity_floor, "
    "severity_id, severity_factors"
)


def _snapshot(test_url: str) -> list[dict]:
    """Dump the comparable incident columns in key order."""
    with psycopg.connect(test_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {_COLUMNS} FROM incidents ORDER BY correlation_key")
            rows = cur.fetchall()
    assert rows is not None
    return [dict(row) for row in rows]


def _incidents() -> list[dict]:
    """Build two deterministic incidents from hand-written fixtures."""
    attack = AttackDictionary.from_compact(_COMPACT)
    findings = [
        make_finding("f1", 0, ["T1083"], host="web01", user="alice"),
        make_finding("f2", 5, ["T1059"], host="web01", user="alice"),
        make_finding("f3", 10, ["T1083"], host="db01", user="bob"),
    ]
    events = {
        "auth-1": make_auth("auth-1", 1, host="web01"),
        "auth-2": make_auth("auth-2", 2, host="web01"),
    }
    return correlate_findings(findings, events, attack)  # type: ignore[return-value]


@pytest.mark.integration
def test_migration_0003_applies_twice_idempotently() -> None:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        applied = migrate(test_url)
        assert "0003_severity_factors.sql" in applied
        assert migrate(test_url) == []

        # File-level idempotency: executing 0003 directly, twice, is safe.
        sql_text = (Path(MIGRATIONS_DIR) / "0003_severity_factors.sql").read_text(
            encoding="utf-8"
        )
        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute(sql_text)
                cur.execute(sql_text)
            conn.commit()

        with psycopg.connect(test_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT column_name, data_type, is_nullable, column_default "
                    "FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'incidents' "
                    "AND column_name = 'severity_factors'"
                )
                row = cur.fetchone()
        assert row is not None
        assert row[1] == "jsonb"
        assert row[2] == "NO"
    finally:
        _drop_database(admin_url, name)


@pytest.mark.integration
def test_upsert_incidents_idempotent_rerun() -> None:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        incidents = _incidents()
        assert len(incidents) == 2

        assert upsert_incidents(test_url, incidents) == 2
        assert stored_incident_count(test_url) == 2
        before = _snapshot(test_url)

        # Re-running over the same data leaves the same rows.
        assert upsert_incidents(test_url, incidents) == 2
        assert stored_incident_count(test_url) == 2
        assert _snapshot(test_url) == before

        # The explanation and the window survive the round trip.
        by_key = {row["correlation_key"]: row for row in before}
        first = by_key[incidents[0]["correlation_key"]]
        assert first["severity_factors"]["factor_1_attack_stage"]
        assert first["severity_factors"]["factor_4_success_vs_attempt"] == {
            "fired": False,
            "contribution": "failures alone add nothing",
        }
        assert first["first_seen"] == ms_to_timestamptz(incidents[0]["first_seen"])
        assert first["last_seen"] == ms_to_timestamptz(incidents[0]["last_seen"])
        assert set(first) == {
            "correlation_key",
            "title",
            "entity_keys",
            "techniques",
            "event_uids",
            "first_seen",
            "last_seen",
            "deterministic_score",
            "severity_floor",
            "severity_id",
            "severity_factors",
        }
    finally:
        _drop_database(admin_url, name)


def _severity(test_url: str, key: str) -> int:
    """Return the stored ``severity_id`` for one correlation key."""
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT severity_id FROM incidents WHERE correlation_key = %s",
                (key,),
            )
            row = cur.fetchone()
    assert row is not None
    return int(row[0])


@pytest.mark.integration
def test_upsert_keeps_model_raised_severity_then_resets() -> None:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        incidents = _incidents()
        upsert_incidents(test_url, incidents)
        key = incidents[0]["correlation_key"]
        floor = incidents[0]["severity_floor"]

        # A model raises severity one level; a same-floor re-run keeps it.
        with psycopg.connect(test_url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE incidents SET severity_id = %s WHERE correlation_key = %s",
                    (floor + 1, key),
                )
        upsert_incidents(test_url, incidents)
        assert _severity(test_url, key) == floor + 1

        # A higher floor re-run resets to the new floor (CHECK holds).
        raised = [dict(incident) for incident in incidents]
        for item in raised:
            item["severity_floor"] = item["severity_floor"] + 2
            item["severity_id"] = item["severity_floor"]
        upsert_incidents(test_url, raised)
        assert _severity(test_url, key) == floor + 2
    finally:
        _drop_database(admin_url, name)
