"""Corvus-group gating for learned-rule attribution.

A finding is a learned-rule finding ONLY when its alert carries at least
one Corvus group (``corvus_shadow``, ``corvus_active`` or
``corvus_<sigma id>``); the native id and the Sigma group must then agree
on the same stored row. Findings without any Corvus group are normal
findings even when their rule id lies in the learned range. All alerts
are the verbatim live fixtures from ``tests/fixtures/wazuh_live``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from corvus.live.attribution import attribution_for_finding
from corvus.normalize.wazuh import map_alert, parse_wazuh_time

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh_live"

SIGMA_SHADOW = "7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"
SIGMA_OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _doc(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _hit(doc: dict[str, Any], doc_id: str) -> dict[str, Any]:
    return {
        "_index": "wazuh-alerts-4.x-2026-11-01",
        "_id": doc_id,
        "_source": doc,
        "sort": [parse_wazuh_time(doc["timestamp"]), doc_id],
    }


def _row(
    record_id: int, native: int, sigma: str, status: str, version: int = 1
) -> dict[str, Any]:
    return {
        "id": record_id,
        "title": f"rule {record_id}",
        "native_rule_id": native,
        "version": version,
        "status": status,
        "lineage": {"sigma_rule_id": sigma, "version": version},
    }


def _finding(rule_id: str, groups: list[str], doc_id: str = "alert-doc-x") -> Any:
    doc = copy.deepcopy(_doc("shadow_sudo_100000"))
    doc["rule"]["id"] = rule_id
    doc["rule"]["groups"] = groups
    doc["id"] = doc_id
    finding, event, _ = map_alert(_hit(doc, doc_id))
    assert event is not None
    return finding


def _stored() -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]]]:
    shadow = _row(7, 100000, SIGMA_SHADOW, "shadow", 2)
    active = _row(9, 100010, SIGMA_OTHER, "active", 1)
    by_native = {100000: shadow, 100010: active}
    by_sigma = {SIGMA_SHADOW: shadow, SIGMA_OTHER: active}
    return by_native, by_sigma


def test_foreign_id_matching_stored_native_without_groups_is_normal() -> None:
    """A foreign rule reusing stored native id 100000, minus Corvus groups."""
    by_native, by_sigma = _stored()
    finding = _finding("100000", ["sudo", "pam"], "alert-doc-a")
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is False
    assert not stamp.get("unknown_learned_rule")
    assert stamp["muted"] is False
    assert "corvus_learned_rule" not in finding.unmapped
    assert "corvus_unknown_learned_rule" not in finding.unmapped


def test_foreign_in_range_id_without_groups_is_normal() -> None:
    """Stock-style custom id 100001 with no stored row and no groups."""
    by_native, by_sigma = _stored()
    finding = _finding("100001", ["local", "syslog"], "alert-doc-b")
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is False
    assert not stamp.get("unknown_learned_rule")
    assert stamp["muted"] is False
    assert "corvus_unknown_learned_rule" not in finding.unmapped


def test_foreign_active_row_id_without_groups_is_normal() -> None:
    """Even the id of an ACTIVE learned row is normal without Corvus groups."""
    by_native, by_sigma = _stored()
    finding = _finding("100010", ["authentication", "pam"], "alert-doc-c")
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is False
    assert not stamp.get("unknown_learned_rule")
    assert stamp["muted"] is False
    assert "corvus_learned_rule" not in finding.unmapped


def test_shipped_rule_with_only_sigma_group_is_unknown() -> None:
    """Out-of-range id plus a `corvus_<sigma>` group: disagree, muted."""
    by_native, by_sigma = _stored()
    finding = _finding("5710", ["syslog", f"corvus_{SIGMA_SHADOW}"], "alert-doc-d")
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is False
    assert stamp["unknown_learned_rule"] is True
    assert stamp["muted"] is True
    assert "corvus_learned_rule" not in finding.unmapped
    assert finding.unmapped["corvus_unknown_learned_rule"]["native_rule_id"] == 5710


def test_id_and_group_disagreeing_is_unknown() -> None:
    """Native id of row 7 with the Sigma group of row 9: muted unknown."""
    by_native, by_sigma = _stored()
    finding = _finding("100000", [f"corvus_{SIGMA_OTHER}"], "alert-doc-e")
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is False
    assert stamp["unknown_learned_rule"] is True
    assert stamp["muted"] is True
    assert "corvus_learned_rule" not in finding.unmapped


def test_agreeing_id_and_group_resolve_shadow() -> None:
    """The verbatim shadow sudo line still resolves through both joins."""
    by_native, by_sigma = _stored()
    finding, _, _ = map_alert(_hit(_doc("shadow_sudo_100000"), "alert-doc-f"))
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is True
    assert stamp["rule_db_id"] == 7
    assert stamp["mode"] == "shadow"
    assert stamp["shadow"] is True
    assert stamp["muted"] is True


def test_agreeing_id_and_group_resolve_active() -> None:
    """An active row with matching id and `corvus_active` group contributes."""
    by_native, by_sigma = _stored()
    finding = _finding(
        "100010", [f"corvus_{SIGMA_OTHER}", "corvus_active"], "alert-doc-g"
    )
    stamp = attribution_for_finding(finding, by_native, by_sigma)
    assert stamp["resolved"] is True
    assert stamp["rule_db_id"] == 9
    assert stamp["mode"] == "active"
    assert stamp["shadow"] is False
    assert stamp["muted"] is False
    assert finding.unmapped["corvus_learned_rule"]["rule_db_id"] == 9
