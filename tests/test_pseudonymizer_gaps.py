"""Gap coverage for cloud-bound pseudonymization.

Each test sends a registered entity through ``prepare_payload`` with a
cloud destination and asserts the adversarial spelling maps to the same
pseudonym (or is neutralized): URL-encoded separators, ``_``/``-``
joined names, non-canonical IPv4 spellings, entity-valued dict keys,
and base64-encoded blobs. Scanner-discovered values keep strict
boundaries; benign blobs stay byte-identical.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from corvus.guardrails.payload import prepare_payload
from corvus.llm.config import BackendConfig
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls


def _pg_url() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    migrate(test_url)
    return admin_url, name, test_url


def _cloud() -> BackendConfig:
    return BackendConfig(
        purpose="analysis",
        model="muse-spark-1.3",
        base_url="https://models.example.net/v1",
        trust="cloud",
        concurrency=4,
        requests_per_minute=30,
        max_input_tokens=65536,
        max_output_tokens=6000,
        api_key="TEST-API-KEY-VALUE-7",
    )


def _send(
    pg_url: str, payload: Any, entities: list[tuple[str, str]] | None = None
) -> str:
    prepared = prepare_payload(
        payload, _cloud(), "visible", database_url=pg_url, entities=entities
    )
    return json.dumps(prepared.payload)


def test_url_encoded_separator_maps_to_same_pseudonym() -> None:
    """`ana%40example.com` hides the same registered e-mail entity."""
    admin_url, name, pg_url = _pg_url()
    try:
        entities = [("email", "ana@example.com")]
        plain = _send(pg_url, {"note": "login by ana@example.com seen"}, entities)
        encoded = _send(pg_url, {"note": "login by ana%40example.com seen"}, entities)
        assert "ana@example.com" not in plain
        assert "ana%40example.com" not in encoded
        assert "ana" not in encoded
        assert "EMAIL-0001" in encoded
        assert "EMAIL-0001" in plain
    finally:
        _drop_database(admin_url, name)


def test_underscore_dash_joined_registered_value_replaced() -> None:
    """`svc_deploy_bot_backup` and `prefix-web01-suffix` hide registered names."""
    admin_url, name, pg_url = _pg_url()
    try:
        entities = [("user", "deploy_bot"), ("host", "web01")]
        dumped = _send(
            pg_url,
            {"note": "run svc_deploy_bot_backup on prefix-web01-suffix now"},
            entities,
        )
        assert "deploy_bot" not in dumped
        assert "web01" not in dumped.lower().replace("host-0001", "")
        assert "USER-0001" in dumped
        assert "HOST-0001" in dumped
    finally:
        _drop_database(admin_url, name)


def test_scanner_discovered_value_keeps_strict_boundaries() -> None:
    """A scanner-only name joined by `_` is left alone (not registered)."""
    admin_url, name, pg_url = _pg_url()
    try:
        line = "run svc_backup_admin_backup; net user backup_admin /add"
        dumped = _send(pg_url, {"cmd_line": line})
        # The standalone occurrence is hidden; the joined form stays.
        assert "svc_backup_admin_backup" in dumped
        assert dumped.count("USER-") == 1
    finally:
        _drop_database(admin_url, name)


def test_ipv4_variant_spellings_share_one_pseudonym() -> None:
    """Padded, spaced and hex IPv4 spellings map to the same pseudonym."""
    admin_url, name, pg_url = _pg_url()
    try:
        entities = [("ip", "10.70.1.20")]
        canonical = _send(pg_url, {"note": "saw 10.70.1.20 today"}, entities)
        assert "IP-0001" in canonical
        for spelling in ("010.070.001.020", "10 . 70 . 1 . 20", "0x0A460114"):
            dumped = _send(pg_url, {"note": f"saw {spelling} today"}, entities)
            assert spelling not in dumped, spelling
            assert "IP-0001" in dumped, spelling
            assert "10.70.1.20" not in dumped, spelling
    finally:
        _drop_database(admin_url, name)


def test_ipv4_variants_found_without_registration() -> None:
    """Variant spellings are discovered by the free-text scan itself."""
    admin_url, name, pg_url = _pg_url()
    try:
        for spelling in ("010.070.001.020", "10 . 70 . 1 . 20", "0x0A460114"):
            dumped = _send(pg_url, {"note": f"beacon {spelling} done"})
            assert spelling not in dumped, spelling
            assert "IP-0001" in dumped, spelling
    finally:
        _drop_database(admin_url, name)


def test_entity_valued_dict_keys_pseudonymized() -> None:
    """Dict keys holding a registered entity are replaced, structure kept."""
    admin_url, name, pg_url = _pg_url()
    try:
        entities = [("user", "bob")]
        dumped = _send(
            pg_url,
            {
                "bob": 1,
                "nested": {"alias-bob": 2, "username": "bob"},
                "user": {"name": "bob"},
            },
            entities,
        )
        assert '"bob"' not in dumped
        assert "alias-bob" not in dumped
        assert "USER-0001" in dumped
        # Structural keys keep their spelling.
        assert '"username"' in dumped
        assert '"user"' in dumped
        assert '"name"' in dumped
    finally:
        _drop_database(admin_url, name)


def _b64_utf16le(text: str) -> str:
    return base64.b64encode(text.encode("utf-16le")).decode("ascii")


def _b64_utf8(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def test_powershell_encoded_command_blob_neutralized() -> None:
    """A `-EncodedCommand` blob decoding to a registered entity is masked."""
    admin_url, name, pg_url = _pg_url()
    try:
        blob = _b64_utf16le("IEX connect back as deploy_bot now")
        assert len(blob) >= 24
        dumped = _send(
            pg_url,
            {"cmd_line": f"powershell -EncodedCommand {blob}"},
            [("user", "deploy_bot")],
        )
        assert blob not in dumped
        assert "deploy_bot" not in dumped
        assert "[ENCODED:contains-entity]" in dumped
    finally:
        _drop_database(admin_url, name)


def test_base64_utf8_token_neutralized() -> None:
    """Any long base64 token decoding (UTF-8) to an entity is masked."""
    admin_url, name, pg_url = _pg_url()
    try:
        blob = _b64_utf8("run daily sync for operator2 account check")
        assert len(blob) >= 24
        dumped = _send(
            pg_url,
            {"cmd_line": f"tool --data {blob} done"},
            [("user", "operator2")],
        )
        assert blob not in dumped
        assert "operator2" not in dumped
        assert "[ENCODED:contains-entity]" in dumped
    finally:
        _drop_database(admin_url, name)


def test_benign_and_short_blobs_stay() -> None:
    """Blobs without entities and short tokens stay verbatim."""
    admin_url, name, pg_url = _pg_url()
    try:
        benign = _b64_utf8("Write-Host hello world from automation daily")
        short = _b64_utf8("deploy_bot")
        assert len(benign) >= 24
        assert len(short) < 24
        dumped = _send(
            pg_url,
            {"cmd_line": f"tool --data {benign} then {short} end"},
            [("user", "deploy_bot")],
        )
        assert benign in dumped
        assert short in dumped
    finally:
        _drop_database(admin_url, name)


def _hex_utf8(text: str) -> str:
    return text.encode("utf-8").hex()


def test_hex_encoded_entity_masked() -> None:
    """A lowercase hex blob decoding to a registered user is masked."""
    admin_url, name, pg_url = _pg_url()
    try:
        blob = _hex_utf8("run sync for deploy_bot account check")
        assert len(blob) >= 12 and len(blob) % 2 == 0
        dumped = _send(
            pg_url,
            {"cmd_line": f"tool acct={blob} done"},
            [("user", "deploy_bot")],
        )
        assert blob not in dumped
        assert "deploy_bot" not in dumped
        assert "[ENCODED:contains-entity]" in dumped
    finally:
        _drop_database(admin_url, name)


def test_uppercase_hex_proctitle_masked() -> None:
    """Uppercase hex (auditd style) decoding to user and IP is masked."""
    admin_url, name, pg_url = _pg_url()
    try:
        blob = _hex_utf8("ssh svc_backup@10.70.1.20").upper()
        dumped = _send(
            pg_url,
            {"cmd_line": f"auditd proctitle={blob} end"},
            [("user", "svc_backup"), ("ip", "10.70.1.20")],
        )
        assert blob not in dumped
        assert "svc_backup" not in dumped
        assert "[ENCODED:contains-entity]" in dumped
    finally:
        _drop_database(admin_url, name)


def test_benign_and_short_hex_stays() -> None:
    """Hex without entities, odd-length runs and short runs stay verbatim."""
    admin_url, name, pg_url = _pg_url()
    try:
        benign = _hex_utf8("Write-Host hello world from automation daily")
        short = _hex_utf8("abcde")
        odd = "abc"
        assert len(benign) >= 12 and len(benign) % 2 == 0
        dumped = _send(
            pg_url,
            {"cmd_line": f"tool --data {benign} then {short} then {odd} end"},
            [("user", "deploy_bot")],
        )
        assert benign in dumped
        assert short in dumped
        assert odd in dumped
        assert "[ENCODED:contains-entity]" not in dumped
    finally:
        _drop_database(admin_url, name)


def test_decimal_integer_ip_replaced() -> None:
    """A decimal-integer IPv4 of a registered IP is replaced (str and int)."""
    admin_url, name, pg_url = _pg_url()
    try:
        packed = int.from_bytes(bytes((10, 70, 1, 20)), "big")
        assert packed == 172359956
        dumped = _send(
            pg_url,
            {"cmd_line": f"probe src={packed} done"},
            [("ip", "10.70.1.20")],
        )
        assert str(packed) not in dumped
        assert "10.70.1.20" not in dumped
        assert "IP-0001" in dumped
        dumped = _send(
            pg_url,
            {"src": packed},
            [("ip", "10.70.1.20")],
        )
        assert str(packed) not in dumped
        assert "IP-0001" in dumped
    finally:
        _drop_database(admin_url, name)


def test_unrelated_integers_stay() -> None:
    """Integers that are no registered IP stay byte-identical."""
    admin_url, name, pg_url = _pg_url()
    try:
        dumped = _send(
            pg_url,
            {"count": 172359957, "port": 443, "flag": True},
            [("ip", "10.70.1.20")],
        )
        assert "172359957" in dumped
        assert "443" in dumped
        assert "true" in dumped
    finally:
        _drop_database(admin_url, name)


def test_ip_match_body_covers_variant_spellings() -> None:
    """Unit pin: variant spellings resolve without the free-text scanner.

    Mutating ``_ip_match_body`` to return None must fail this test:
    the table holds only the canonical quad (as when the IP was
    registered from a typed field), so only the variant matcher can
    replace the padded, spaced and hex spellings.
    """
    from corvus.guardrails.pseudonymizer import _ip_match_body
    from tests.oracle_pseudonymizer import legacy_replace_free_text

    assert _ip_match_body("10.70.1.20") is not None
    assert _ip_match_body("::1") is None
    table = {"10.70.1.20": ("IP-0001", "ip")}
    registered = frozenset({("ip", "10.70.1.20")})
    for spelling in (
        "010.070.001.020",
        "10 . 70 . 1 . 20",
        "0x0A460114",
        "0x0a460114",
    ):
        out = legacy_replace_free_text(f"saw {spelling} today", dict(table), registered)
        assert out == "saw IP-0001 today", spelling
