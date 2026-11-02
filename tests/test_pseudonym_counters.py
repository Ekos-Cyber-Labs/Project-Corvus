"""Monotonic pseudonym numbers and purge locking (migration 0012).

Numbers used to come from ``max(existing) + 1``, so purging the
highest rows reissued their HOST-/DOMAIN- numbers to later entities.
Numbers now come from a per-kind counter that only advances. Backed
by the shared throwaway-Postgres guard; no paid API calls.
"""

from __future__ import annotations

import threading
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from corvus.guardrails.pseudonymizer import (
    Pseudonymizer,
    purge_file_pseudonyms,
)
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def counter_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield Pseudonymizer(test_url), test_url
    finally:
        _drop_database(admin_url, name)


def _insert_pseudonym(test_url: str, kind: str, value: str, token: str) -> None:
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO pseudonyms (entity_kind, entity_value, pseudonym)"
                " VALUES (%s, %s, %s)",
                (kind, value, token),
            )


def _counter(test_url: str, kind: str) -> int | None:
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT next_number FROM pseudonym_counters WHERE entity_kind = %s",
                (kind,),
            )
            row = cur.fetchone()
            return int(row[0]) if row is not None else None


def test_purge_then_register_never_reuses(counter_db: Any) -> None:
    """Purging HOST-0002/0003 never hands those numbers to a new host."""
    pseudo, test_url = counter_db
    assert pseudo.get_or_create("host", "web01") == "HOST-0001"
    _insert_pseudonym(test_url, "host", "evil.exe", "HOST-0002")
    _insert_pseudonym(test_url, "host", "malware.dll", "HOST-0003")
    applied = purge_file_pseudonyms(test_url, apply=True)
    assert applied["candidates"] == 2
    assert applied["deleted"] == 2
    token = pseudo.get_or_create("host", "db01")
    assert token == "HOST-0004", token
    assert _counter(test_url, "host") == 5


def test_counter_seeded_from_pre_counter_rows(counter_db: Any) -> None:
    """Legacy rows inserted before any allocation still reserve numbers."""
    pseudo, test_url = counter_db
    _insert_pseudonym(test_url, "domain", "old-corp.example", "DOMAIN-0041")
    assert pseudo.get_or_create("domain", "fresh.example") == "DOMAIN-0042"
    assert _counter(test_url, "domain") == 43


def test_shown_and_emitted_only_references_are_kept(counter_db: Any) -> None:
    """Tokens cited only by shown/emitted sets survive the purge."""
    _, test_url = counter_db
    _insert_pseudonym(test_url, "host", "evil.exe", "HOST-0009")
    _insert_pseudonym(test_url, "host", "malware.dll", "HOST-0010")
    _insert_pseudonym(test_url, "host", "trojan.sys", "HOST-0011")
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, severity_floor, severity_id)"
                " VALUES ('corr-counter', 3, 3) RETURNING id"
            )
            incident_id = int(cur.fetchone()[0])
            cur.execute(
                "INSERT INTO agent_steps (incident_id, step_number, tool,"
                " arguments, shown_pseudonyms, emitted_pseudonyms)"
                " VALUES (%s, 1, 'get_events', %s, %s, %s)",
                (
                    incident_id,
                    Jsonb({"host": "HOST-0001"}),
                    Jsonb(["HOST-0009"]),
                    Jsonb([]),
                ),
            )
            cur.execute(
                "INSERT INTO agent_steps (incident_id, step_number, tool,"
                " arguments, shown_pseudonyms, emitted_pseudonyms)"
                " VALUES (%s, 2, 'get_events', %s, %s, %s)",
                (
                    incident_id,
                    Jsonb({"host": "HOST-0001"}),
                    Jsonb([]),
                    Jsonb(["HOST-0010"]),
                ),
            )
    dry = purge_file_pseudonyms(test_url)
    assert dry == {
        "candidates": 3,
        "referenced_kept": 2,
        "deleted": 0,
        "deletable": 1,
    }
    applied = purge_file_pseudonyms(test_url, apply=True)
    assert applied["deleted"] == 1
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pseudonym FROM pseudonyms")
            remaining = {str(row[0]) for row in cur.fetchall()}
    assert remaining == {"HOST-0009", "HOST-0010"}


def test_purge_takes_the_allocation_lock(counter_db: Any) -> None:
    """The purge waits while another session holds the advisory lock."""
    _, test_url = counter_db
    blocker = psycopg.connect(test_url, autocommit=True)
    try:
        with blocker.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(hashtext('corvus:pseudonyms'))")
        done: list[bool] = []
        thread = threading.Thread(
            target=lambda: done.append(
                purge_file_pseudonyms(test_url, apply=True)["deleted"] >= 0
            )
        )
        thread.start()
        thread.join(timeout=3)
        assert not done, "purge must wait for the allocation lock"
        with blocker.cursor() as cur:
            cur.execute("SELECT pg_advisory_unlock(hashtext('corvus:pseudonyms'))")
        thread.join(timeout=10)
        assert done == [True]
    finally:
        blocker.close()


def test_concurrent_register_and_purge_stays_unique(counter_db: Any) -> None:
    """Concurrent allocation and purge never collide or lose a number."""
    pseudo, test_url = counter_db
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []
    allocated: list[str | None] = []
    ident = threading.get_ident()

    def _register() -> None:
        try:
            barrier.wait(timeout=10)
            worker = Pseudonymizer(test_url)
            for index in range(15):
                allocated.append(
                    worker.get_or_create("host", f"concurrent-{ident}-{index}")
                )
        except BaseException as exc:  # noqa: BLE001 - collected and asserted
            errors.append(exc)

    def _purge() -> None:
        try:
            barrier.wait(timeout=10)
            purge_file_pseudonyms(test_url, apply=True)
        except BaseException as exc:  # noqa: BLE001 - collected and asserted
            errors.append(exc)

    threads = [threading.Thread(target=_register), threading.Thread(target=_purge)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert len(allocated) == 15
    assert len(set(allocated)) == 15
    numbers = sorted(int(str(token).rsplit("-", 1)[-1]) for token in allocated)
    assert numbers == list(range(numbers[0], numbers[0] + 15))
    assert _counter(test_url, "host") == numbers[-1] + 1


def test_transition_rule_invalid_lineage_is_value_error(counter_db: Any) -> None:
    """A non-object lineage fails as ValueError, never raw TypeError."""
    from corvus.learning.rules import transition_rule

    _, test_url = counter_db
    with psycopg.connect(test_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rules (title, sigma_text, native_rule_id, version,"
                " status, lineage) VALUES (%s, %s, %s, %s, 'candidate', %s)"
                " RETURNING id",
                (
                    "bad lineage",
                    "title: bad\nid: 00000000-0000-4000-8000-000000000000\n"
                    "status: experimental\n",
                    100001,
                    1,
                    Jsonb(5),
                ),
            )
            row = cur.fetchone()
            assert row is not None
            rule_id = int(row[0])
    with pytest.raises(ValueError, match="lineage"):
        transition_rule(test_url, rule_id, "shadow", approver="tester", reason="probe")
