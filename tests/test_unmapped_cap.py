"""Caps on values that never reach a typed slot.

Typed slots and ``raw_data`` leaves already truncate at 65536
characters. The remaining hole was every value kept whole under
``unmapped`` (Windows leftover payload fields; Wazuh ``audit.*``,
``syscheck.*``, ``linux.*`` and ``wazuh_id`` entries) and the Wazuh
``rule.mitre`` tactic/technique names that land in ``attacks[]``.
A 5 MB string in any of those reached the stored event whole.

Every capped site keeps the first 65536 characters (the first 1000
items/keys for lists/dicts) and records the original length under
``<key>_truncated``. Values already within the caps are byte-identical
to the previous output (pinned by the corpora snapshot diff in the
change report). Adversarial inputs below are synthetic and say so.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from corvus.normalize import wazuh
from corvus.normalize.wazuh import WAZUH_RAW_DATA_CAP, WAZUH_UNMAPPED_LIST_CAP
from corvus.normalize.windows import (
    WINDOWS_TEXT_CAP,
    WINDOWS_UNMAPPED_LIST_CAP,
    extract_json_parts,
    make_uid,
    normalize_event,
    sanitize_record,
)
from tests.fixtures import windows_events as fx

WAZUH_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
LINUX_FIXTURES = Path(__file__).parent / "fixtures" / "linux"

CAP = 65536
BIG = 5_000_000


def _normalize_record(record: dict[str, Any]) -> Any:
    """Run a hand-made record through extraction plus normalization."""
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, 1
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid("unmapped-cap", record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _string_leaves(item)]
    if isinstance(value, (list, tuple)):
        return [leaf for item in value for leaf in _string_leaves(item)]
    return []


def _stored_size(value: Any) -> int:
    """Serialized size of a stored ``unmapped`` value."""
    return len(json.dumps(value, default=str, sort_keys=True))


def test_list_caps_match_across_normalizers() -> None:
    """Both normalizers bound leftover list counts at the same length."""
    assert WAZUH_UNMAPPED_LIST_CAP == WINDOWS_UNMAPPED_LIST_CAP
    assert WAZUH_UNMAPPED_LIST_CAP == 1000
    assert WAZUH_RAW_DATA_CAP == WINDOWS_TEXT_CAP == CAP


def test_windows_leftover_at_cap_is_unchanged() -> None:
    """A leftover field of exactly 65536 chars stays byte-identical."""
    record = fx.flat_sysmon_process()
    record["CustomField"] = "C" * CAP
    event = _normalize_record(record)
    assert event.unmapped.get("CustomField") == "C" * CAP
    assert "CustomField_truncated" not in event.unmapped


def test_windows_leftover_one_over_truncates() -> None:
    """A leftover field of 65537 chars keeps 65536 plus its length."""
    record = fx.flat_sysmon_process()
    record["CustomField"] = "C" * (CAP + 1)
    event = _normalize_record(record)
    assert event.unmapped.get("CustomField") == "C" * CAP
    assert event.unmapped.get("CustomField_truncated") == CAP + 1


def test_windows_leftover_5mb_string_is_bounded() -> None:
    """A 5 MB leftover string stays a bounded event (synthetic)."""
    record = fx.flat_sysmon_process()
    record["Message"] = "M" * BIG
    event = _normalize_record(record)
    stored = event.unmapped.get("Message")
    assert isinstance(stored, str)
    assert len(stored) == CAP
    assert event.unmapped.get("Message_truncated") == BIG
    assert _stored_size(event.unmapped) < 500_000


def test_windows_leftover_100k_list_is_bounded() -> None:
    """A 100000-item leftover list keeps 1000 items plus its length."""
    record = fx.flat_sysmon_process()
    items = [f"item-{index}" for index in range(100_000)]
    record["CustomList"] = items  # type: ignore[assignment]
    event = _normalize_record(record)
    stored = event.unmapped.get("CustomList")
    assert isinstance(stored, list)
    assert len(stored) == WINDOWS_UNMAPPED_LIST_CAP
    assert stored[0] == "item-0"
    assert event.unmapped.get("CustomList_truncated") == len(
        json.dumps(items, default=str, sort_keys=True)
    )
    assert _stored_size(event.unmapped) <= CAP + 100_000


def test_windows_leftover_nested_dict_5mb_is_bounded() -> None:
    """A ~5 MB deep-and-wide leftover dict stays bounded (synthetic)."""
    record = fx.flat_sysmon_process()
    nested: dict[str, Any] = {}
    for outer in range(20):
        nested[f"group-{outer}"] = {f"key-{inner}": "V" * 13_000 for inner in range(20)}
    original_serial = len(json.dumps(nested, default=str, sort_keys=True))
    assert original_serial > BIG
    record["CustomMap"] = nested  # type: ignore[assignment]
    event = _normalize_record(record)
    assert event.unmapped.get("CustomMap_truncated") == original_serial
    stored_map = event.unmapped.get("CustomMap")
    assert isinstance(stored_map, str)
    assert len(stored_map) == CAP


def test_windows_leftover_nul_and_surrogates_sanitized_and_bounded() -> None:
    """NUL bytes and lone surrogates never reach the stored event."""
    record = fx.flat_sysmon_process()
    record["CustomField"] = "A\x00B\ud800C" * 20_000
    event = _normalize_record(record)
    for leaf in _string_leaves(event.model_dump(exclude={"entity_keys"})):
        assert "\x00" not in leaf
        assert not any(0xD800 <= ord(char) <= 0xDFFF for char in leaf)
    assert event.unmapped.get("CustomField_truncated") == 100_000


def _sudo_hit(**overrides: Any) -> dict[str, Any]:
    """Build a synthetic sudo alert hit (adversarial, not a fixture)."""
    hit = json.loads((WAZUH_FIXTURES / "sudo.json").read_text(encoding="utf-8"))
    source = hit["_source"]
    for key, value in overrides.items():
        source[key] = value
    return hit


def test_wazuh_sudo_tty_5mb_is_bounded() -> None:
    """A 5 MB sudo tty stays bounded on the event (synthetic)."""
    finding, event, _key = wazuh.map_alert(_sudo_hit(tty="T" * BIG))
    assert finding is not None and event is not None
    assert event.unmapped.get("tty") == "T" * CAP
    assert event.unmapped.get("tty_truncated") == BIG


def test_wazuh_unmapped_string_boundaries() -> None:
    """65536 chars stay identical; 65537 truncate with the length kept."""
    _finding, event, _key = wazuh.map_alert(_sudo_hit(pwd="P" * CAP))
    assert event is not None
    assert event.unmapped.get("pwd") == "P" * CAP
    assert "pwd_truncated" not in event.unmapped
    _finding, event, _key = wazuh.map_alert(_sudo_hit(pwd="P" * (CAP + 1)))
    assert event is not None
    assert event.unmapped.get("pwd") == "P" * CAP
    assert event.unmapped.get("pwd_truncated") == CAP + 1


def _linux_doc(name: str) -> dict[str, Any]:
    return json.loads((LINUX_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def test_wazuh_audit_success_5mb_is_bounded() -> None:
    """A 5 MB ``audit.success`` leftover stays bounded (synthetic)."""
    doc = _linux_doc("exec_hex")
    assert isinstance(doc["data"]["audit"], dict)
    doc["data"]["audit"]["success"] = "S" * BIG
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert event is not None
    assert event.unmapped.get("audit.success") == "S" * CAP
    assert event.unmapped.get("audit.success_truncated") == BIG


def test_wazuh_syscheck_extra_100k_list_is_bounded() -> None:
    """A 100000-item syscheck extra value keeps 1000 items (synthetic)."""
    hit = json.loads(
        (WAZUH_FIXTURES / "syscheck_integrity_changed.json").read_text(encoding="utf-8")
    )
    items = [f"entry-{index}" for index in range(100_000)]
    hit["_source"]["data"]["syscheck"]["custom_extra"] = items
    finding, event, _key = wazuh.map_alert(hit)
    assert event is not None
    stored = event.unmapped.get("syscheck.custom_extra")
    assert isinstance(stored, list)
    assert len(stored) == WAZUH_UNMAPPED_LIST_CAP
    assert event.unmapped.get("syscheck.custom_extra_truncated") == len(
        json.dumps(items, default=str, sort_keys=True)
    )
    assert finding is not None
    assert _stored_size(finding.unmapped) <= CAP + 100_000


def test_wazuh_linux_cwd_5mb_is_bounded() -> None:
    """A 5 MB audit CWD stays bounded (synthetic blob)."""
    doc = _linux_doc("exec_hex")
    doc["full_log"] = re.sub(
        r'cwd="[^"]*"', f'cwd="{"W" * BIG}"', doc["full_log"], count=1
    )
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert event is not None
    assert event.unmapped.get("linux.cwd") == "W" * CAP
    assert event.unmapped.get("linux.cwd_truncated") == BIG


def test_wazuh_su_tty_5mb_is_bounded() -> None:
    """A 5 MB su tty stays bounded (synthetic)."""
    doc = _linux_doc("su_rec")
    doc["full_log"] = (
        "2026-10-29T14:25:37.114463+00:00 web01 su[44871]: "
        f"(to deploy) root on {'N' * BIG}"
    )
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert event is not None
    stored = event.unmapped.get("linux.tty")
    assert isinstance(stored, str)
    assert len(stored) == CAP
    assert event.unmapped.get("linux.tty_truncated") == BIG


def test_wazuh_archive_wazuh_id_5mb_is_bounded() -> None:
    """A 5 MB archive ``id`` stays bounded (synthetic)."""
    doc = _linux_doc("sudo_rec")
    doc["id"] = "I" * BIG
    event, key = wazuh.map_archive({"_id": "archive-1", "_source": doc})
    assert key is None
    assert event is not None
    assert event.unmapped.get("wazuh_id") == "I" * CAP
    assert event.unmapped.get("wazuh_id_truncated") == BIG


def _mitre_hit(techniques: Any, tactics: Any, ids: Any) -> dict[str, Any]:
    """Build a synthetic sudo alert hit with a hostile MITRE block."""
    hit = _sudo_hit()
    hit["_source"]["rule"]["mitre"] = {
        "id": ids,
        "tactic": tactics,
        "technique": techniques,
    }
    return hit


def test_wazuh_mitre_technique_5mb_name_is_bounded() -> None:
    """A 5 MB technique name reaches ``attacks[]`` truncated, never lost."""
    big_name = "E" * BIG
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit([big_name], ["Privilege Escalation"], ["T1059"])
    )
    assert finding is not None
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and len(attacks) == 1
    assert attacks[0].technique is not None
    assert attacks[0].technique.uid == "T1059"
    assert attacks[0].technique.name == "E" * CAP
    assert finding.unmapped.get("wazuh.mitre_technique_truncated") == BIG


def test_wazuh_mitre_name_boundaries() -> None:
    """A technique name at the cap stays; one over truncates with length."""
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["N" * CAP], ["Escalation"], ["T1059"])
    )
    assert finding is not None
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and len(attacks) == 1
    assert attacks[0].technique is not None
    assert attacks[0].technique.name == "N" * CAP
    assert "wazuh.mitre_technique_truncated" not in finding.unmapped
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["N" * (CAP + 1)], ["Escalation"], ["T1059"])
    )
    assert finding is not None
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and len(attacks) == 1
    assert attacks[0].technique is not None
    assert attacks[0].technique.name == "N" * CAP
    assert finding.unmapped.get("wazuh.mitre_technique_truncated") == CAP + 1
    tactic_finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["Sudo"], ["A" * CAP], ["TA0004"])
    )
    assert tactic_finding is not None
    assert tactic_finding.finding_info is not None
    tactic_attacks = tactic_finding.finding_info.attacks
    assert tactic_attacks is not None and len(tactic_attacks) == 1
    assert tactic_attacks[0].tactic is not None
    assert tactic_attacks[0].tactic.name == "A" * CAP
    assert "wazuh.mitre_tactic_truncated" not in tactic_finding.unmapped
    tactic_finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["Sudo"], ["A" * (CAP + 1)], ["TA0004"])
    )
    assert tactic_finding is not None
    assert tactic_finding.finding_info is not None
    tactic_attacks = tactic_finding.finding_info.attacks
    assert tactic_attacks is not None and len(tactic_attacks) == 1
    assert tactic_attacks[0].tactic is not None
    assert tactic_attacks[0].tactic.name == "A" * CAP
    assert tactic_finding.unmapped.get("wazuh.mitre_tactic_truncated") == CAP + 1


def test_wazuh_mitre_tactic_5mb_name_is_bounded() -> None:
    """A 5 MB tactic name reaches ``attacks[]`` truncated, never lost."""
    big_name = "A" * BIG
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["Sudo and Sudo Caching"], [big_name], ["TA0004"])
    )
    assert finding is not None
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and len(attacks) == 1
    assert attacks[0].tactic is not None
    assert attacks[0].tactic.uid == "TA0004"
    assert attacks[0].tactic.name == "A" * CAP
    assert finding.unmapped.get("wazuh.mitre_tactic_truncated") == BIG


def test_wazuh_mitre_invalid_id_behaves_as_before() -> None:
    """Ids that fail validation are still skipped, with no marker."""
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["Sudo"], ["Escalation"], ["NOT-A-TECHNIQUE"])
    )
    assert finding is not None
    assert finding.finding_info is not None
    assert finding.finding_info.attacks is None
    assert "wazuh.mitre_technique_truncated" not in finding.unmapped
    assert "wazuh.mitre_tactic_truncated" not in finding.unmapped
    assert "wazuh.mitre_id_truncated" not in finding.unmapped
    junk = "X" * BIG
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["Sudo"], ["Escalation"], [junk])
    )
    assert finding is not None
    assert finding.finding_info is not None
    assert finding.finding_info.attacks is None
    assert "wazuh.mitre_id_truncated" not in finding.unmapped


def test_wazuh_mitre_huge_passing_id_is_bounded() -> None:
    """A 5 MB id that passes validation keeps its entry, capped."""
    junk = "T" + "1" * BIG
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit(["Sudo"], ["Escalation"], [junk])
    )
    assert finding is not None
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and len(attacks) == 1
    assert attacks[0].technique is not None
    assert attacks[0].technique.uid is not None
    assert len(attacks[0].technique.uid) == CAP
    assert attacks[0].technique.uid == junk[:CAP]
    assert finding.unmapped.get("wazuh.mitre_id_truncated") == len(junk)


def test_wazuh_mitre_nonstring_name_is_capped_not_dropped() -> None:
    """A dict technique name is stringified and capped, never dropped."""
    hostile: dict[str, Any] = {"payload": "X" * (BIG)}
    finding, _event, _key = wazuh.map_alert(
        _mitre_hit([copy.deepcopy(hostile)], ["Escalation"], ["T1548.003"])
    )
    assert finding is not None
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and len(attacks) == 1
    assert attacks[0].sub_technique is not None
    assert attacks[0].sub_technique.uid == "T1548.003"
    assert attacks[0].sub_technique.name is not None
    assert len(attacks[0].sub_technique.name) == CAP
    assert finding.unmapped.get("wazuh.mitre_technique_truncated") == len(str(hostile))


def test_wazuh_decoder_conflict_huge_value_is_bounded() -> None:
    """A huge decoder-conflict value stays bounded (synthetic)."""
    doc = _linux_doc("auth")
    doc["data"] = dict(doc.get("data", {}))
    doc["data"]["srcuser"] = "deploy"
    doc["data"]["srcip"] = "I" * BIG
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert event is not None
    conflict = event.unmapped.get("linux.decoder_conflict")
    assert isinstance(conflict, str)
    assert len(conflict) == CAP
    assert event.unmapped.get("linux.decoder_conflict_truncated") == len(
        json.dumps({"user": "deploy", "ip": "I" * BIG}, default=str, sort_keys=True)
    )
