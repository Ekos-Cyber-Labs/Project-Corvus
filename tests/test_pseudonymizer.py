"""Adversarial tests for the stable pseudonymizer.

Backed by throwaway Postgres databases (same guard as the queue
tests): sequence numbers come from Postgres, get-or-create is
race-safe across threads, and canonicalization matches the adapters.
"""

from __future__ import annotations

import threading
from typing import Any

import psycopg
import pytest

from corvus.guardrails.pseudonymizer import (
    FIELD_KINDS,
    KINDS,
    Pseudonymizer,
    canonicalize_domain,
    canonicalize_email,
    scan_entities,
)
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


@pytest.fixture
def pseudo_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield Pseudonymizer(test_url), test_url
    finally:
        _drop_database(admin_url, name)


def _row_count(test_url: str) -> int:
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pseudonyms")
            row = cur.fetchone()
    assert row is not None
    return int(row[0])


def test_kinds_and_prefixes(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    assert pseudo.get_or_create("host", "web01.example.com") == "HOST-0001"
    assert pseudo.get_or_create("user", "bob") == "USER-0001"
    assert pseudo.get_or_create("ip", "192.0.2.10") == "IP-0001"
    assert pseudo.get_or_create("domain", "Example.COM.") == "DOMAIN-0001"
    assert pseudo.get_or_create("email", "Bob@Example.com") == "EMAIL-0001"


def test_sequence_is_per_kind(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    assert pseudo.get_or_create("host", "web01.example.com") == "HOST-0001"
    assert pseudo.get_or_create("host", "web02.example.com") == "HOST-0002"
    assert pseudo.get_or_create("user", "bob") == "USER-0001"


def test_unknown_kind_rejected(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    with pytest.raises(ValueError):
        pseudo.get_or_create("sid", "S-1-5-21-1")


def test_non_string_rejected(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    with pytest.raises(TypeError):
        pseudo.get_or_create("host", None)  # type: ignore[arg-type]


@pytest.mark.parametrize("placeholder", ["", "  ", "-", "n/a", "unknown", "UNKNOWN"])
def test_placeholders_never_get_pseudonyms(pseudo_db: Any, placeholder: str) -> None:
    pseudo, test_url = pseudo_db
    for kind in KINDS:
        assert pseudo.get_or_create(kind, placeholder) is None
    assert _row_count(test_url) == 0


def test_same_entity_across_three_payloads(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    first = pseudo.pseudonymize(
        {"hostname": "WEB01.example.com", "message": "alert from web01 witnessed"}
    )
    second = pseudo.pseudonymize(
        {"hostname": "web01", "message": "web01 reported again"}
    )
    third = pseudo.pseudonymize({"message": "WEB01.example.com seen once more"})
    assert first["hostname"] == second["hostname"] == "HOST-0001"
    assert first["message"] == "alert from HOST-0001 witnessed"
    assert second["message"] == "HOST-0001 reported again"
    assert third["message"] == "HOST-0001 seen once more"


def test_concurrent_create_yields_one_row(pseudo_db: Any) -> None:
    pseudo, test_url = pseudo_db
    results: list[str | None] = [None] * 8
    errors: list[BaseException] = []

    def _worker(slot: int) -> None:
        try:
            results[slot] = pseudo.get_or_create("host", "race01.example.com")
        except BaseException as exc:  # pragma: no cover - test fails below
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(slot,)) for slot in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert set(results) == {"HOST-0001"}
    assert _row_count(test_url) == 1


def test_user_case_insensitive(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    assert pseudo.get_or_create("user", "ADMIN") == "USER-0001"
    assert pseudo.get_or_create("user", "admin") == "USER-0001"


def test_user_domain_forms(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    # The UPN and the DNS-domain backslash form canonicalize alike;
    # a NetBIOS short domain is a different domain (as in Entity).
    assert pseudo.get_or_create("user", "admin@example.com") == "USER-0001"
    assert pseudo.get_or_create("user", "example.com\\admin") == "USER-0001"
    assert pseudo.get_or_create("user", "EXAMPLE\\jdoe") == "USER-0002"


def test_ipv6_address(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    assert pseudo.get_or_create("ip", "2001:db8::1") == "IP-0001"
    assert pseudo.get_or_create("ip", "2001:DB8::1") == "IP-0001"
    # IPv4-mapped IPv6 unwraps to the IPv4 address.
    assert pseudo.get_or_create("ip", "::ffff:192.0.2.5") == "IP-0002"
    assert pseudo.reveal("from IP-0002") == "from 192.0.2.5"


def test_unicode_entity(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    assert pseudo.get_or_create("user", "josé") == "USER-0001"
    assert pseudo.get_or_create("user", "JOSÉ") == "USER-0001"
    out = pseudo.pseudonymize({"user": "josé", "message": "JOSÉ logged on"})
    assert out == {"user": "USER-0001", "message": "USER-0001 logged on"}


def test_free_text_boundaries(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    out = pseudo.pseudonymize(
        {
            "username": "bob",
            "message": "bob ran C:\\bobcat\\bob.exe; contact bob@example.com re bob",
        }
    )
    assert out["username"] == "USER-0001"
    # E-mail-shaped spans are entities of their own (EMAIL-0001), while
    # "bob" inside "bobcat"/"bob.exe" is left alone by the boundary rule.
    assert out["message"] == (
        "USER-0001 ran C:\\bobcat\\bob.exe; contact EMAIL-0001 re USER-0001"
    )


def test_host_suffix_rules(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    out = pseudo.pseudonymize(
        {
            "hostname": "web01",
            "message": "WEB01.example.com booted; ran web01.exe; ping web01.corp",
        }
    )
    # Multi-label FQDN matches; a filename and a single-label suffix
    # stay untouched (documented limitation).
    assert out["message"] == ("HOST-0001 booted; ran web01.exe; ping web01.corp")


def test_user_name_under_user_parent(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    out = pseudo.pseudonymize(
        {"actor": {"user": {"name": "bob", "domain": "example.com"}}}
    )
    assert out["actor"]["user"]["name"] == "USER-0001"
    assert out["actor"]["user"]["domain"] == "DOMAIN-0001"


def test_generic_name_key_untouched(pseudo_db: Any) -> None:
    # A bare "name" key is not a user field, so bare "bob" stays; but
    # "bob.exe" is FQDN-shaped and the scanner fails closed on it.
    pseudo, test_url = pseudo_db
    out = pseudo.pseudonymize({"name": "bob", "process": {"name": "bob.exe"}})
    assert out == {"name": "bob", "process": {"name": "DOMAIN-0001"}}
    assert _row_count(test_url) == 1


def test_reveal_roundtrip_and_unknown(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    pseudo.get_or_create("host", "web01.example.com")
    assert pseudo.reveal("event on HOST-0001 closed") == "event on web01 closed"
    assert pseudo.reveal("event on HOST-9999 closed") == "event on HOST-9999 closed"
    assert pseudo.reveal("nothing to map") == "nothing to map"


def test_reveal_rejects_non_string(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    with pytest.raises(TypeError):
        pseudo.reveal(None)  # type: ignore[arg-type]


def test_pseudonym_never_contains_value(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    for kind, raw in (
        ("host", "web01.example.com"),
        ("user", "bob"),
        ("ip", "192.0.2.10"),
        ("domain", "example.com"),
        ("email", "bob@example.com"),
    ):
        pseudonym = pseudo.get_or_create(kind, raw)
        assert pseudonym is not None
        assert raw.lower() not in pseudonym.lower()


def test_canonicalize_domain_email_helpers() -> None:
    assert canonicalize_domain("Example.COM.") == "example.com"
    assert canonicalize_domain("-") is None
    assert canonicalize_email("Bob@Example.com") == "bob@example.com"
    assert canonicalize_email("not-an-email") is None
    assert canonicalize_email("-") is None


def test_field_kinds_cover_expected_keys() -> None:
    for key in ("hostname", "username", "src_ip", "domain", "email"):
        assert key in FIELD_KINDS
    assert "name" not in FIELD_KINDS


def test_scan_finds_each_category() -> None:
    assert ("ip", "198.51.100.7") in scan_entities("curl http://198.51.100.7/x")
    assert ("ip", "2001:db8::99") in scan_entities("ping 2001:db8::99.")
    assert ("email", "carol@db01.example.com") in scan_entities(
        "scp a.sh carol@db01.example.com:/tmp"
    )
    assert ("domain", "intranet.corp.example.com") in scan_entities(
        "nslookup intranet.corp.example.com"
    )
    assert ("host", "nas02") in scan_entities("net use \\\\nas02\\backups")
    assert ("user", "corp\\dave") in scan_entities("runas /user:corp\\dave")
    assert ("user", "backup_admin") in scan_entities("net user backup_admin /add")
    assert ("user", "svc_sql") in scan_entities("write C:\\Users\\svc_sql\\x done")
    assert ("user", "erin") in scan_entities("cat /home/erin/.ssh/id_rsa")
    assert ("user", "deploy_key") in scan_entities("ssh -u deploy_key web09")
    assert ("user", "EAST\\jrivera") in scan_entities("whoami EAST\\jrivera")


def test_scan_prefers_longest_span() -> None:
    assert scan_entities("contact bob@example.com re bob") == [
        ("email", "bob@example.com")
    ]
    assert scan_entities("C:\\Users\\bob\\a.sh") == [("user", "bob")]
    assert scan_entities("at 14:03:00") == []
    assert scan_entities("AA:BB:CC:DD:EE:FF") == []
    assert scan_entities("version 999.1.1.1 ok") == []


def test_scan_bare_words_not_found() -> None:
    # Bare words in no recognizable position are invisible to the
    # scanner by design; they are hidden only via register().
    assert scan_entities("seen from jump host jump01 by frank") == []
    with pytest.raises(TypeError):
        scan_entities(None)  # type: ignore[arg-type]


def test_scan_feeds_pseudonymize(pseudo_db: Any) -> None:
    pseudo, _ = pseudo_db
    out = pseudo.pseudonymize(
        {"cmd_line": "ping 203.0.113.9 ; nslookup intranet.corp.example.com"}
    )
    assert out == {"cmd_line": "ping IP-0001 ; nslookup DOMAIN-0001"}


def test_register_bulk_and_validation(pseudo_db: Any) -> None:
    pseudo, test_url = pseudo_db
    mapping = pseudo.register([("host", "jump01"), ("user", "frank"), ("host", "-")])
    assert mapping == {("host", "jump01"): "HOST-0001", ("user", "frank"): "USER-0001"}
    assert _row_count(test_url) == 2
    with pytest.raises(ValueError):
        pseudo.register([("sid", "S-1-5-21-1")])
    with pytest.raises(TypeError):
        pseudo.register([("host", None)])  # type: ignore[list-item]
    assert pseudo.register([]) == {}


def test_registered_typed_entity_hidden_in_other_free_text(
    pseudo_db: Any,
) -> None:
    pseudo, _ = pseudo_db
    pseudo.register([("host", "jump01"), ("user", "frank")])
    out = pseudo.pseudonymize({"note": "seen from jump host jump01 by frank"})
    assert out == {"note": "seen from jump host HOST-0001 by USER-0001"}
