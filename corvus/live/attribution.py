"""Learned-rule attribution for Wazuh alert findings (no model calls).

A finding whose Wazuh rule id is in 100000-120000 (or that carries a
``corvus_<sigma id>`` group) was produced by a learned rule. This
module joins it to its stored rule row:

- exact join: the alert rule id equals the row's ``native_rule_id``;
- pair join: a deployed rule ships as a sudo/auditd pair of native
  ids under one ``corvus_<sigma id>`` group (the second id is the
  next free id above the anchor at export time, so it is NOT
  ``anchor + 1`` in general), so a ``corvus_<sigma id>`` group naming
  a stored Sigma id joins to that row whatever the native id is.

The finding is stamped in ``unmapped`` (kept, flagged, never
trusted blindly):

- resolved: ``corvus_learned_rule`` with the rule record id, Sigma
  id, version, mode (the row status: ``shadow`` or ``active``),
  lineage id (the Sigma id again, which is what ``lineage`` keys
  on), the native id, and whether it is a shadow or pair-secondary
  match;
- unresolvable but in the learned range (or carrying an unresolvable
  ``corvus_`` group): kept with ``corvus_unknown_learned_rule`` and
  never trusted.

Shadow findings (group ``corvus_shadow``) and unknown learned
findings never raise incident severity: :func:`mutes_severity`
decides that here so correlation and the poll share one predicate.
Only a resolved ``active`` rule without the shadow group contributes
its severity.
"""

from __future__ import annotations

from typing import Any

from corvus.learning.rules import NATIVE_ID_MAX, NATIVE_ID_MIN

__all__ = [
    "LEARNED_ID_MAX",
    "LEARNED_ID_MIN",
    "MODE_GROUPS",
    "attribution_for_finding",
    "finding_muted",
    "finding_rule_id",
    "finding_sigma_groups",
    "is_shadow_finding",
    "learned_refs_for_uids",
    "mutes_severity",
    "resolve_learned",
]

#: Learned-rule native id range (mirrors the rules table CHECK).
LEARNED_ID_MIN = NATIVE_ID_MIN
LEARNED_ID_MAX = NATIVE_ID_MAX

#: Inner Wazuh group markers (see corvus/learning/wazuh_xml.py).
MODE_GROUPS = frozenset({"corvus_shadow", "corvus_active"})

#: Group prefix wrapping one rule per source (``corvus_<sigma id>``).
GROUP_PREFIX = "corvus_"


def finding_rule_id(finding: Any) -> str | None:
    """Return the Wazuh rule id from the finding analytic, if present."""
    info = getattr(finding, "finding_info", None)
    analytic = getattr(info, "analytic", None) if info is not None else None
    uid = getattr(analytic, "uid", None) if analytic is not None else None
    if uid is None:
        return None
    text = str(uid).strip()
    return text or None


def finding_sigma_groups(finding: Any) -> list[str]:
    """Return the ``corvus_<sigma id>`` groups on the finding."""
    info = getattr(finding, "finding_info", None)
    analytic = getattr(info, "analytic", None) if info is not None else None
    category = getattr(analytic, "category", None) if analytic is not None else None
    if not category:
        return []
    groups = [part.strip() for part in str(category).split(",")]
    return [
        group
        for group in groups
        if group.startswith(GROUP_PREFIX) and group not in MODE_GROUPS
    ]


def is_shadow_finding(finding: Any) -> bool:
    """Return True when the finding carries the ``corvus_shadow`` group."""
    info = getattr(finding, "finding_info", None)
    analytic = getattr(info, "analytic", None) if info is not None else None
    category = getattr(analytic, "category", None) if analytic is not None else None
    if not category:
        return False
    return "corvus_shadow" in [part.strip() for part in str(category).split(",")]


def _native_id(rule_id: str | None) -> int | None:
    """Parse a numeric Wazuh rule id, else None (kept, never raised)."""
    if rule_id is None:
        return None
    text = rule_id.strip()
    if not text.isdigit():
        return None
    return int(text)


def resolve_learned(
    rule_id: str | None,
    sigma_groups: list[str],
    rows_by_native: dict[int, dict[str, Any]],
    rows_by_sigma: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Join one alert rule reference to its stored rule row.

    ``rows_by_native`` maps ``native_rule_id`` to the stored row;
    ``rows_by_sigma`` maps ``lineage.sigma_rule_id`` to the stored
    row. Returns a stamp dict (see :func:`attribution_for_finding`);
    ``resolved`` is False with ``unknown_learned_rule`` True when the
    reference is learned-range but matches no stored rule.
    """
    native = _native_id(rule_id)
    in_range = native is not None and LEARNED_ID_MIN <= native <= LEARNED_ID_MAX
    row: dict[str, Any] | None = None
    via: str | None = None
    if native is not None and native in rows_by_native:
        row = rows_by_native[native]
        via = "native"
    if row is None:
        for group in sigma_groups:
            sigma_id = group[len(GROUP_PREFIX) :]
            if sigma_id and sigma_id in rows_by_sigma:
                row = rows_by_sigma[sigma_id]
                via = "sigma_group"
                break
    if row is not None:
        lineage = row.get("lineage") or {}
        return {
            "resolved": True,
            "rule_db_id": int(row["id"]),
            "sigma_rule_id": str(lineage.get("sigma_rule_id") or ""),
            "version": int(row["version"]),
            "mode": str(row.get("status") or ""),
            "lineage_id": str(lineage.get("sigma_rule_id") or ""),
            "native_rule_id": native,
            "via": via,
            "in_learned_range": in_range,
        }
    if in_range or sigma_groups:
        return {
            "resolved": False,
            "unknown_learned_rule": True,
            "native_rule_id": native,
            "sigma_groups": list(sigma_groups),
            "in_learned_range": in_range,
        }
    return {"resolved": False, "learned": False}


def mutes_severity(stamp: dict[str, Any], shadow: bool) -> bool:
    """Return True when the finding must not raise incident severity.

    Shadow findings (group ``corvus_shadow``) never raise severity,
    unknown learned findings are never trusted, and only a resolved
    ``active`` rule contributes its severity (a candidate, shadow,
    rolled-back or archived row stays muted even without the group).
    """
    if shadow:
        return True
    if stamp.get("unknown_learned_rule"):
        return True
    if not stamp.get("resolved"):
        return False
    return stamp.get("mode") != "active"


def finding_muted(finding: Any) -> bool:
    """Return True when a stamped finding must not raise severity.

    Reads the same stamps :func:`attribution_for_finding` writes, so
    correlation needs no database: shadow findings, unknown learned
    findings, and non-active learned rules are muted. Unstamped
    findings (shipped rules, replay data) are never muted.
    """
    unmapped = getattr(finding, "unmapped", None)
    if not isinstance(unmapped, dict):
        return False
    if unmapped.get("corvus_shadow"):
        return True
    if unmapped.get("corvus_unknown_learned_rule"):
        return True
    ref = unmapped.get("corvus_learned_rule")
    if isinstance(ref, dict):
        return ref.get("mode") != "active"
    return False


def learned_refs_for_uids(
    uids: list[str], findings_by_uid: dict[str, Any]
) -> list[dict[str, Any]]:
    """Collect the learned-rule references behind finding uids.

    One entry per learned rule (rule record id, Sigma id, version,
    mode shadow/active, lineage id, native id, shadow/unknown flags,
    finding count), sorted by rule id then native id. Findings
    without a stamp contribute nothing.
    """
    grouped: dict[tuple[str, Any], dict[str, Any]] = {}
    for uid in uids:
        finding = findings_by_uid.get(str(uid))
        if finding is None:
            continue
        unmapped = getattr(finding, "unmapped", None)
        if not isinstance(unmapped, dict):
            continue
        ref = unmapped.get("corvus_learned_rule")
        unknown = unmapped.get("corvus_unknown_learned_rule")
        shadow = bool(unmapped.get("corvus_shadow"))
        if isinstance(ref, dict):
            key = ("r", ref.get("rule_db_id"))
            entry = grouped.setdefault(
                key,
                {
                    "rule_db_id": ref.get("rule_db_id"),
                    "sigma_rule_id": ref.get("sigma_rule_id"),
                    "version": ref.get("version"),
                    "mode": ref.get("mode"),
                    "lineage_id": ref.get("lineage_id"),
                    "native_rule_id": ref.get("native_rule_id"),
                    "shadow": shadow,
                    "unknown": False,
                    "findings": 0,
                },
            )
            entry["findings"] += 1
        elif isinstance(unknown, dict):
            key = ("u", unknown.get("native_rule_id"))
            entry = grouped.setdefault(
                key,
                {
                    "rule_db_id": None,
                    "sigma_rule_id": None,
                    "version": None,
                    "mode": "unknown",
                    "lineage_id": None,
                    "native_rule_id": unknown.get("native_rule_id"),
                    "shadow": shadow,
                    "unknown": True,
                    "findings": 0,
                },
            )
            entry["findings"] += 1
    return sorted(
        grouped.values(),
        key=lambda entry: (entry["rule_db_id"] or 0, entry["native_rule_id"] or 0),
    )


def attribution_for_finding(
    finding: Any,
    rows_by_native: dict[int, dict[str, Any]],
    rows_by_sigma: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Stamp one finding with its learned-rule reference; return the stamp.

    The stamp lands in ``finding.unmapped`` (``corvus_learned_rule``
    when resolved, ``corvus_unknown_learned_rule`` when learned-range
    but unresolvable, plus ``corvus_shadow`` for the shadow group) and
    is also returned for the incident and cycle bookkeeping.
    Non-learned findings get an empty stamp and no new keys.
    """
    rule_id = finding_rule_id(finding)
    groups = finding_sigma_groups(finding)
    shadow = is_shadow_finding(finding)
    stamp = resolve_learned(rule_id, groups, rows_by_native, rows_by_sigma)
    unmapped = getattr(finding, "unmapped", None)
    if not isinstance(unmapped, dict):
        try:
            finding.unmapped = {}
        except Exception:
            return {**stamp, "shadow": shadow, "muted": True}
        unmapped = finding.unmapped
    if stamp.get("resolved"):
        unmapped["corvus_learned_rule"] = {
            "rule_db_id": stamp["rule_db_id"],
            "sigma_rule_id": stamp["sigma_rule_id"],
            "version": stamp["version"],
            "mode": stamp["mode"],
            "lineage_id": stamp["lineage_id"],
            "native_rule_id": stamp["native_rule_id"],
            "via": stamp["via"],
        }
        if shadow:
            unmapped["corvus_shadow"] = True
    elif stamp.get("unknown_learned_rule"):
        unmapped["corvus_unknown_learned_rule"] = {
            "native_rule_id": stamp["native_rule_id"],
            "sigma_groups": stamp["sigma_groups"],
        }
        if shadow:
            unmapped["corvus_shadow"] = True
    elif shadow:
        unmapped["corvus_shadow"] = True
    return {**stamp, "shadow": shadow, "muted": mutes_severity(stamp, shadow)}
