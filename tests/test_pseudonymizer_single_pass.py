"""Differential pin: shipped free-text replacement equals the frozen oracle.

For every payload in the corpora, one table snapshot (built once by
:meth:`Pseudonymizer._build_table`) feeds both the shipped
:class:`_FreeTextReplacer` and the frozen per-entry oracle
(:func:`tests.oracle_pseudonymizer.legacy_replace_free_text`, a
byte-for-byte copy of the committed implementation): the replaced
payload and the emitted pseudonym set must be byte for byte
identical. Any divergence is a product bug, not a test expectation
to update. If a rule change intentionally diverges, name the rule,
explain why, and get maintainer approval before re-freezing.

Covered corpora (finding A):

1. The table-collision leak: host rows for ``ieuser``/``users``/
   ``desktop`` plus a ``C:\\Users\\IEUser\\...`` free-text user found
   by the scan in the same call, in every row-insertion order.
2. Tables holding colliding raw values of different kinds.
3. Payloads where the scan discovers entities not yet in the table.
4. Real triaged payloads of the local deployment database when it is
   present (read-only copy of its ``pseudonyms`` and triaged
   ``incident_analyses`` rows into the scratch test database; a clear
   skip marker when absent) plus the synthetic fixtures.
5. 2,000 seeded random strings built from table values wrapped in
   boundary characters.
"""

from __future__ import annotations

import base64
import itertools
import json
import random
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest

from corvus.guardrails.pseudonymizer import _FreeTextReplacer
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls
from tests.fixtures import windows_events as fx
from tests.fixtures.siem_events import make_siem_fixture_events
from tests.oracle_pseudonymizer import legacy_replace_free_text

WAZUH_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
LINUX_FIXTURES = Path(__file__).parent / "fixtures" / "linux"

#: Fixed seed for the boundary fuzz (case 5): the same 2,000 strings
#: on every run.
FUZZ_SEED = 20261102
FUZZ_CASES = 2000

#: Boundary characters wrapped around table values in the fuzz.
FUZZ_BOUNDARIES = [
    "\\",
    "/",
    ".",
    "_",
    "-",
    ":",
    "@",
    " ",
    ",",
    ";",
    "=",
    "(",
    ")",
    '"',
    "'",
    "|",
]


@pytest.fixture
def diff_db() -> Any:
    """Throwaway Postgres with migrations applied (guarded, never skips)."""
    from corvus.guardrails.pseudonymizer import Pseudonymizer

    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield Pseudonymizer(test_url)
    finally:
        _drop_database(admin_url, name)


class _OracleReplacer:
    """Adapter running the frozen oracle behind the replacer interface."""

    def __init__(
        self, table: dict[str, tuple[str, str]], registered: frozenset[Any]
    ) -> None:
        self._table = table
        self._registered = registered

    def replace(self, text: str, emitted: set[str] | None = None) -> str:
        return legacy_replace_free_text(text, self._table, self._registered, emitted)


def _run_both(pseudo: Any, dumped: Any) -> tuple[Any, set[str], Any, set[str]]:
    """Run shipped and oracle passes over one snapshot; return both."""
    table, registered, needles = pseudo._build_table(dumped)
    emitted_new: set[str] = set()
    new = pseudo._replace(
        dumped,
        table,
        registered=registered,
        needles=needles,
        emitted=emitted_new,
        replacer=_FreeTextReplacer(table, registered),
    )
    emitted_old: set[str] = set()
    old = pseudo._replace(
        dumped,
        table,
        registered=registered,
        needles=needles,
        emitted=emitted_old,
        replacer=_OracleReplacer(table, registered),
    )
    return new, emitted_new, old, emitted_old


def _assert_same(
    new: Any,
    emitted_new: set[str],
    old: Any,
    emitted_old: set[str],
    where: str,
) -> None:
    assert new == old, f"{where}: replaced payload diverged"
    assert emitted_new == emitted_old, f"{where}: emitted set diverged"


def _seed_deployment(pseudo: Any) -> None:
    """Register a deployment-wide entity mix (typed plus free-text-only)."""
    pseudo.register(
        [
            ("host", "web01.example.com"),
            ("host", "db01.example.com"),
            ("host", "secretws01.example.com"),
            ("host", "workstation5"),
            ("user", "EXAMPLE\\jdoe"),
            ("user", "EXAMPLE\\svc-backup"),
            ("user", "bob"),
            ("ip", "192.0.2.10"),
            ("ip", "198.51.100.23"),
            ("ip", "203.0.113.7"),
            ("ip", "10.70.1.20"),
            ("domain", "example.com"),
            ("domain", "download.example.com"),
            ("email", "bob@example.com"),
        ]
    )


def _corpus() -> list[Any]:
    payloads: list[Any] = []
    for event in make_siem_fixture_events():
        payloads.append(event.model_dump(mode="json"))
    payloads.extend(
        [
            fx.flat_sysmon_process(),
            fx.flat_sysmon_network(),
            fx.flat_sysmon_file(),
            fx.flat_security_logon(success=True),
            fx.flat_security_task(),
            fx.flat_taskscheduler_106(),
            fx.flat_sysmon_access(),
            fx.flat_powershell_script(),
            fx.flat_powershell_module(),
            fx.flat_sysmon_registry_value(),
            fx.flat_windows_powershell_pipeline(),
            fx.flat_unicode_process(),
        ]
    )
    for name in (
        "sudo.json",
        "sshd_success.json",
        "sshd_failure.json",
        "archive_sshd.json",
        "syscheck_integrity_changed.json",
    ):
        payloads.append(json.loads((WAZUH_FIXTURES / name).read_text()))
    for name in ("auth.json", "exec_hex.json", "conn.json"):
        try:
            payloads.append(json.loads((LINUX_FIXTURES / name).read_text()))
        except OSError:
            continue
    blob = base64.b64encode(b"run as bob on web01").decode()
    ping_msg = "C:\\Windows\\System32\\cmd.exe /c ping secretws01.example.com"
    bob_msg = "bob ran C:\\bobcat\\bob.exe; contact bob@example.com re bob"
    spaced = "user=bob, src=173343012 and 010.070.001.020 spaced 10 . 70 . 1 . 20"
    payloads.extend(
        [
            {"message": ping_msg},
            {"message": bob_msg},
            {"message": "seen from jump host jump01 by frank"},
            {"message": "on workstation5. then on workstation55!"},
            {"message": "\"bob\" and 'jdoe' logged on (EXAMPLE\\jdoe)."},
            {"message": spaced},
            {"message": f"encoded {blob} plus 0x0A460114 hex ip"},
            {"message": "login user%40example.com from WEB01.example.com"},
            {"message": "svc_bob_backup ran it, then myworkstation5 stayed"},
            {"message": "\\\\FILESRV02\\share and C:\\Users\\jdoe\\Desktop\\note.txt"},
            {"message": "echo HOST-9999 stays literal while bob hides"},
            {"message": "héllo JOSÉ wörld 数据"},
            {"t": ["nested", ("tuple", {"bob": "key bob value"})]},
            {"user": {"name": "svc-backup"}, "host": "DB01.example.com"},
        ]
    )
    return payloads


def test_synthetic_fixtures_match_oracle(diff_db: Any) -> None:
    """Same snapshot, both passes: identical payload and emitted set."""
    _seed_deployment(diff_db)
    corpus = _corpus()
    assert len(corpus) > 20
    for position, payload in enumerate(corpus):
        dumped = json.loads(json.dumps(payload, default=str))
        new, emitted_new, old, emitted_old = _run_both(diff_db, dumped)
        _assert_same(new, emitted_new, old, emitted_old, f"payload {position}")


def _fresh_test_url() -> tuple[str, str, str]:
    """Create a throwaway database; return (admin_url, test_url, name)."""
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    migrate(test_url)
    return admin_url, test_url, name


def test_table_collision_first_call_hides_scanned_user() -> None:
    """Case (1): the first call already hides the scan-found user name.

    Host rows for ordinary words (``ieuser``/``users``/``desktop``)
    collide case-insensitively with the ``IEUser`` profile owner the
    scan finds in this very call. Every row-insertion order is tried;
    on every call the real name must be gone, the ``Desktop`` path
    component must stay verbatim, and the shipped pass must equal the
    oracle. This test fails on the pre-fix single-pass replacer: its
    first call returns the text unchanged.
    """
    from corvus.guardrails.pseudonymizer import Pseudonymizer

    rows = [
        ("host", "ieuser", "HOST-0008"),
        ("host", "users", "HOST-0006"),
        ("host", "desktop", "HOST-0007"),
    ]
    payload = {"m": "C:\\Users\\IEUser\\Desktop\\a.dmp created"}
    for rank, order in enumerate(itertools.permutations(rows)):
        admin_url, test_url, name = _fresh_test_url()
        try:
            with psycopg.connect(test_url, autocommit=True) as conn:
                with conn.cursor() as cur:
                    for kind, value, pseudo in order:
                        cur.execute(
                            "INSERT INTO pseudonyms"
                            " (entity_kind, entity_value, pseudonym)"
                            " VALUES (%s, %s, %s)",
                            (kind, value, pseudo),
                        )
            for call in (1, 2, 3):
                dumped = json.loads(json.dumps(payload))
                new, emitted_new, old, emitted_old = _run_both(
                    Pseudonymizer(test_url), dumped
                )
                where = f"order {rank} call {call}"
                _assert_same(new, emitted_new, old, emitted_old, where)
                assert "ieuser" not in new["m"].lower(), where
                assert "USER-0001" in new["m"], where
                assert "Desktop" in new["m"], where
            reused = Pseudonymizer(test_url)
            for call in (1, 2, 3):
                dumped = json.loads(json.dumps(payload))
                new, emitted_new, old, emitted_old = _run_both(reused, dumped)
                where = f"order {rank} reused call {call}"
                _assert_same(new, emitted_new, old, emitted_old, where)
                assert "ieuser" not in new["m"].lower(), where
        finally:
            _drop_database(admin_url, name)


def test_colliding_raw_values_of_different_kinds(diff_db: Any) -> None:
    """Case (2): same-spelling rows of different kinds both take part."""
    with psycopg.connect(diff_db._database_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            for kind, value, pseudo in [
                ("host", "bob", "HOST-0101"),
                ("user", "bob", "USER-0101"),
                ("host", "MARTIN", "HOST-0102"),
                ("user", "martin", "USER-0102"),
                ("host", "web01", "HOST-0103"),
                ("domain", "web01.example.com", "DOMAIN-0103"),
            ]:
                cur.execute(
                    "INSERT INTO pseudonyms (entity_kind, entity_value, pseudonym)"
                    " VALUES (%s, %s, %s)",
                    (kind, value, pseudo),
                )
    for position, payload in enumerate(
        [
            {"m": "saw bob today"},
            {"m": "saw MARTIN with martin"},
            {"m": "open WEB01.example.com and web01 now"},
            {"m": "C:\\bob\\bob.exe by bob"},
        ]
    ):
        dumped = json.loads(json.dumps(payload))
        new, emitted_new, old, emitted_old = _run_both(diff_db, dumped)
        _assert_same(new, emitted_new, old, emitted_old, f"case {position}")
    check = json.loads(json.dumps({"m": "saw bob today"}))
    new, _, _, _ = _run_both(diff_db, check)
    assert "bob" not in new["m"].lower()
    check = json.loads(json.dumps({"m": "saw MARTIN with martin"}))
    new, _, _, _ = _run_both(diff_db, check)
    assert "martin" not in new["m"].lower()
    check = json.loads(json.dumps({"m": "open WEB01.example.com and web01 now"}))
    new, _, _, _ = _run_both(diff_db, check)
    assert "web01.example.com" not in new["m"].lower()


def test_scan_discovers_entities_not_in_table() -> None:
    """Case (3): entities found only by the scan are hidden at once."""
    from corvus.guardrails.pseudonymizer import Pseudonymizer

    admin_url, test_url, name = _fresh_test_url()
    try:
        pseudo = Pseudonymizer(test_url)
        payloads = [
            {"m": "C:\\Users\\IEUser\\Desktop\\a.dmp created"},
            {"m": "run \\\\FILESRV02\\share\\tool.exe soon"},
            {"m": "contact ana@example.com about 010.070.001.020"},
            {"m": "net user backup_admin /add and go"},
            {"m": "Welcome EXAMPLE\\jdoe, home /home/jdoe ready"},
        ]
        for position, payload in enumerate(payloads):
            dumped = json.loads(json.dumps(payload))
            new, emitted_new, old, emitted_old = _run_both(pseudo, dumped)
            _assert_same(new, emitted_new, old, emitted_old, f"payload {position}")
        probe = json.loads(json.dumps(payloads[0]))
        new, _, _, _ = _run_both(pseudo, probe)
        assert "ieuser" not in new["m"].lower()
        probe = json.loads(json.dumps(payloads[1]))
        new, _, _, _ = _run_both(pseudo, probe)
        assert "filesrv02" not in new["m"].lower()
        probe = json.loads(json.dumps(payloads[2]))
        new, _, _, _ = _run_both(pseudo, probe)
        assert "ana@example.com" not in new["m"]
        assert "010.070.001.020" not in new["m"]
    finally:
        _drop_database(admin_url, name)


def _deployment_url() -> str | None:
    """Return the local deployment URL (same server, ``corvus`` db)."""
    import os

    database_url = os.environ.get("DATABASE_URL", "")
    parsed = urlparse(database_url)
    if not parsed.hostname or not parsed.path:
        return None
    return urlunparse(parsed._replace(path="/corvus"))


def test_real_triaged_payloads_match_oracle(diff_db: Any) -> None:
    """Case (4): 20 real triaged payloads equal the oracle.

    Reads the local deployment database read-only (SELECTs only, one
    implicit transaction, never written) and copies its ``pseudonyms``
    rows plus the first 20 triaged ``incident_analyses`` payloads into
    the scratch test database. Skips with a clear marker when the
    deployment database is absent or holds no triaged payloads.
    """
    deploy_url = _deployment_url()
    if deploy_url is None:
        pytest.skip("local deployment database absent: no DATABASE_URL")
    try:
        with psycopg.connect(deploy_url, connect_timeout=5) as src:
            with src.cursor() as cur:
                cur.execute(
                    "SELECT entity_kind, entity_value, pseudonym FROM pseudonyms"
                )
                rows = [(str(k), str(v), str(p)) for k, v, p in cur.fetchall()]
                cur.execute(
                    "SELECT id, payload FROM incident_analyses"
                    " WHERE stage='triage' ORDER BY id LIMIT 20"
                )
                analyses = [(int(i), cur_payload) for i, cur_payload in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001 - deployment DB is optional
        pytest.skip(f"local deployment database absent ({type(exc).__name__})")
    if not analyses:
        pytest.skip("local deployment database holds no triaged payloads")
    with psycopg.connect(diff_db._database_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            for kind, value, pseudo in rows:
                cur.execute(
                    "INSERT INTO pseudonyms (entity_kind, entity_value, pseudonym)"
                    " VALUES (%s, %s, %s)"
                    " ON CONFLICT (entity_kind, entity_value) DO NOTHING",
                    (kind, value, pseudo),
                )
    assert len(analyses) >= 1
    for analysis_id, payload in analyses:
        dumped = json.loads(json.dumps(payload, default=str))
        new, emitted_new, old, emitted_old = _run_both(diff_db, dumped)
        _assert_same(new, emitted_new, old, emitted_old, f"triage {analysis_id}")


def test_boundary_fuzz_matches_oracle(diff_db: Any) -> None:
    """Case (5): 2,000 seeded boundary strings equal the oracle."""
    _seed_deployment(diff_db)
    diff_db.register(
        [
            ("host", "bob"),
            ("host", "MARTIN"),
            ("user", "martin"),
            ("host", "ieuser"),
            ("host", "users"),
            ("host", "desktop"),
        ]
    )
    seed_dumped = {"seed": "ana@example.com 10.70.1.20 web01 ws bob IEUser"}
    table, registered, _needles = diff_db._build_table(seed_dumped)
    shipped = _FreeTextReplacer(table, registered)
    values = list(table)
    values.extend(
        value.replace("@", "%40")
        for value in values
        if "@" in value and len(value) >= 3
    )
    rng = random.Random(FUZZ_SEED)
    for case in range(FUZZ_CASES):
        first = rng.choice(values)
        pre = "".join(rng.choice(FUZZ_BOUNDARIES) for _ in range(rng.randint(0, 2)))
        post = "".join(rng.choice(FUZZ_BOUNDARIES) for _ in range(rng.randint(0, 2)))
        if rng.random() < 0.4:
            second = rng.choice(values)
            mid = "".join(rng.choice(FUZZ_BOUNDARIES) for _ in range(rng.randint(1, 3)))
            text = f"seen {pre}{first}{mid}{second}{post} ok"
        else:
            text = f"seen {pre}{first}{post} ok"
        emitted_new: set[str] = set()
        emitted_old: set[str] = set()
        new = shipped.replace(text, emitted_new)
        old = legacy_replace_free_text(text, table, registered, emitted_old)
        assert new == old, f"fuzz case {case} diverged: {text!r} -> {new!r} vs {old!r}"
        assert emitted_new == emitted_old, f"fuzz case {case} emitted diverged"
