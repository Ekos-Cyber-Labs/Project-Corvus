"""Explainable severity floor for correlated incidents.

Only factors 1 (ATT&CK stage), 2 (breadth) and 4 (success vs attempt)
are scored; factor numbering follows the pipeline design so a later
factor 3 slots in without renumbering. The floor maps to OCSF
``severity_id`` 1..5; 6 (Fatal) is never produced. Every factor records
its inputs and its contribution, JSON-serializable, in
``severity_factors``.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "CRITICAL",
    "HIGH",
    "LOW",
    "MAX_FLOOR",
    "MEDIUM",
    "STAGE_LEVELS",
    "check_stage_coverage",
    "primary_of",
    "severity_floor",
]

#: OCSF severity levels used by the floor.
LOW = 2
MEDIUM = 3
HIGH = 4
CRITICAL = 5

#: The floor never reaches Fatal (6).
MAX_FLOOR = CRITICAL

#: Fallback stage when an incident carries no ATT&CK tactics at all.
_NO_TACTIC_LEVEL = 1

#: ATT&CK tactic shortname -> stage level. Keys are the shortnames of
#: the loaded ATT&CK dictionary's ``tactic_order`` (ATT&CK v20 splits
#: Defense Evasion into ``stealth`` and ``defense-impairment``); see
#: :func:`check_stage_coverage`. Unknown shortnames raise in
#: :func:`severity_floor` instead of defaulting.
STAGE_LEVELS: dict[str, int] = {
    "reconnaissance": LOW,
    "resource-development": LOW,
    "discovery": LOW,
    "initial-access": MEDIUM,
    "execution": MEDIUM,
    "persistence": MEDIUM,
    "privilege-escalation": MEDIUM,
    "stealth": MEDIUM,
    "defense-impairment": MEDIUM,
    "credential-access": HIGH,
    "lateral-movement": HIGH,
    "collection": HIGH,
    "command-and-control": HIGH,
    "exfiltration": HIGH,
    "impact": HIGH,
}

#: Breadth that lifts the floor one level (factor 2).
BREADTH_BONUS_AT = 3

#: Breadth that, together with a High stage, admits Critical (factor 2).
CRITICAL_BREADTH_AT = 4


def primary_of(
    tactics: list[str] | tuple[str, ...] | set[str] | frozenset[str],
    tactic_order: list[str] | tuple[str, ...],
) -> str | None:
    """Return the most advanced of ``tactics``, or None when empty.

    Most advanced means the highest stage level, breaking ties by the
    dictionary's ``tactic_order`` (later in the matrix wins), so the
    choice is deterministic. Tactics without a stage level raise
    instead of defaulting.
    """
    shortnames = set(tactics)
    unknown = check_stage_coverage(shortnames)
    if unknown:
        raise ValueError(f"tactics without a stage level: {sorted(unknown)}")
    if not shortnames:
        return None
    rank = {short: index for index, short in enumerate(tactic_order)}
    return max(shortnames, key=lambda short: (STAGE_LEVELS[short], rank.get(short, -1)))


def check_stage_coverage(
    tactic_order: list[str] | tuple[str, ...] | set[str] | frozenset[str],
) -> list[str]:
    """Return tactic shortnames in ``tactic_order`` missing from the stage map.

    Empty means every tactic of the loaded dictionary has a stage. A
    future ATT&CK release with a new tactic shows up here (and raises in
    :func:`severity_floor`) instead of silently defaulting.
    """
    return [short for short in tactic_order if short not in STAGE_LEVELS]


def severity_floor(
    tactics: list[str],
    primary_tactics: list[str],
    tactic_order: list[str] | tuple[str, ...],
    max_finding_severity: int,
    success_fired: bool,
) -> tuple[int, dict[str, Any]]:
    """Compute the severity floor from the numbered factors.

    ``tactics`` are the incident's distinct ATT&CK tactic shortnames
    (factor 1 takes the most advanced over all of them);
    ``primary_tactics`` are the distinct per-finding primary tactics
    (each finding contributes its own most advanced tactic; factor 2
    breadth counts these, so one multi-tactic technique never earns
    the breadth bonus alone). ``tactic_order`` is the loaded
    dictionary's matrix order (breaks ties for the most advanced
    tactic deterministically). ``max_finding_severity`` is the highest
    OCSF ``severity_id`` of the member findings (rule levels:
    1 informational, 2 low, ...). ``success_fired`` says factor 4
    observed a successful authentication after enough failures.

    Order of application: factor 1 sets the base, factor 2 adds one
    level for breadth (gated for Critical), the informational/low cap
    holds single-tactic quiet incidents at Low, then factor 4 raises to
    at least High (success evidence overrides the quiet cap). Returns
    the floor and the ``severity_factors`` explanation.
    """
    unknown = check_stage_coverage(set(tactics) | set(primary_tactics))
    if unknown:
        raise ValueError(f"tactics without a stage level: {sorted(unknown)}")
    breadth = len(set(primary_tactics))
    most_advanced = primary_of(tactics, tactic_order)
    if most_advanced is not None:
        stage_level = STAGE_LEVELS[most_advanced]
    else:
        stage_level = _NO_TACTIC_LEVEL

    floor = stage_level
    factor_1: dict[str, Any] = {
        "tactics": sorted(set(tactics)),
        "most_advanced_tactic": most_advanced,
        "level": stage_level,
        "contribution": f"sets the base to {stage_level}",
    }

    breadth_added = breadth >= BREADTH_BONUS_AT
    if breadth_added:
        floor += 1
    if floor >= CRITICAL and not (
        stage_level == HIGH and breadth >= CRITICAL_BREADTH_AT
    ):
        floor = HIGH
    floor = min(floor, MAX_FLOOR)
    factor_2: dict[str, Any] = {
        "primary_tactics": sorted(set(primary_tactics)),
        "distinct_tactics": breadth,
        "added_level": breadth_added,
        "contribution": ("adds one level" if breadth_added else "adds nothing"),
    }

    low_capped = max_finding_severity <= LOW and breadth <= 1
    if low_capped:
        floor = min(floor, LOW)
    level_cap: dict[str, Any] = {
        "applied": low_capped,
        "max_finding_severity": max_finding_severity,
        "contribution": (
            "holds informational/low single-tactic incidents at Low"
            if low_capped
            else "does not apply"
        ),
    }

    if success_fired:
        floor = max(floor, HIGH)
    factor_4: dict[str, Any] = {
        "fired": success_fired,
        "contribution": (
            "raises the floor to at least High"
            if success_fired
            else "failures alone add nothing"
        ),
    }

    floor = max(1, min(floor, MAX_FLOOR))
    factors = {
        "factor_1_attack_stage": factor_1,
        "factor_2_breadth": factor_2,
        "level_cap": level_cap,
        "factor_4_success_vs_attempt": factor_4,
    }
    return floor, factors
