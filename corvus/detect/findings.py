"""Build OCSF Detection Findings (2004) from rule matches.

One finding per (rule, event) pair: rule id and title in the typed
finding/analytic fields, severity from the rule level, ATT&CK tags
resolved through ``corvus/attack`` (revoked ids resolved to their
replacement, deprecated ids dropped, tactic-only entries dropped when
a technique entry covers their tactic) in the typed attacks field,
the matched event uid in ``finding_info.related_events``, and the
matched event's context in one top-level ``evidences`` entry (an
attribute of the 2004 finding itself, not of ``finding_info``; the
finding carries no actor or endpoints). Finding
uids are deterministic (rule id plus event uid), so a re-run emits
the same findings with no duplicates.

Rule metadata the typed slots cannot hold stays in ``unmapped``:
``sigma_author`` names the Sigma rule author, which the Detection
Rule License 1.1 requires in views showing matches; the versioned
rule permalink goes to ``finding_info.src_url``. Ground-truth tables
(techniques, tactics from the eval harness) never enter findings.
"""

from __future__ import annotations

import hashlib
from typing import Any

from corvus.attack.dictionary import AttackDictionary, normalize_id
from corvus.detect.engine import MatchedEvent
from corvus.detect.rules import CompiledRule
from corvus.normalize.ocsf import (
    Actor,
    Analytic,
    AttackRef,
    DetectionFinding,
    Device,
    Endpoint,
    Evidence,
    File,
    FindingInfo,
    Metadata,
    Process,
    Product,
    RelatedEvent,
    TacticRef,
    TechniqueRef,
)

__all__ = [
    "SEVERITY_IDS",
    "SEVERITY_NAMES",
    "SIGMA_TAG_PREFIX",
    "attacks_for_tags",
    "build_finding",
    "finding_uid",
]

#: Sigma rule level to OCSF severity id (informational 1 .. critical 5).
SEVERITY_IDS = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

#: OCSF severity id to caption (pinned OCSF 1.9.0 ``dictionary.json``).
SEVERITY_NAMES = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}

#: Tag namespace carrying ATT&CK references in Sigma rules.
SIGMA_TAG_PREFIX = "attack"

#: Pinned SigmaHQ release tag the rule permalinks point at.
SIGMA_RELEASE_TAG = "r2026-07-01"


def finding_uid(rule_id: str, event_uid: str) -> str:
    """Return the deterministic finding uid for one rule match."""
    seed = f"{rule_id}#{event_uid}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def attacks_for_tags(
    attack: AttackDictionary, tags: list[tuple[str, str]], version: str
) -> tuple[list[AttackRef], int]:
    """Build typed attacks for Sigma ``attack.*`` tags.

    Technique tags resolve through ``revoked-by`` (a revoked id
    becomes its replacement); tactic shortname tags attach the tactic
    with no technique; deprecated or unknown ids and other namespaces
    are dropped. Tactic ``uid`` is the ``TA####`` external id (pinned
    OCSF 1.9.0 ``objects/tactic.json``). A tactic-only entry is
    dropped when the same tactic already appears in an entry carrying
    a technique; tactic-only entries for uncovered tactics stay.
    Returns the attacks plus the dropped-tag count.
    """
    attacks: list[AttackRef] = []
    seen: set[tuple[str | None, str | None, str | None]] = set()
    dropped = 0
    for namespace, name in tags:
        if namespace != SIGMA_TAG_PREFIX:
            continue
        resolved = _resolve_technique(attack, name)
        if resolved is not None:
            technique_uid, technique_name, sub_uid, sub_name, tactics = resolved
            pairs: list[tuple[str | None, str | None]] = list(tactics) or [(None, None)]
            for tactic_uid, display in pairs:
                key = (tactic_uid, technique_uid, sub_uid)
                if key in seen:
                    continue
                seen.add(key)
                attacks.append(
                    AttackRef(
                        tactic=(
                            TacticRef(uid=tactic_uid, name=display)
                            if tactic_uid is not None
                            else None
                        ),
                        technique=TechniqueRef(uid=technique_uid, name=technique_name),
                        sub_technique=(
                            TechniqueRef(uid=sub_uid, name=sub_name)
                            if sub_uid is not None
                            else None
                        ),
                        version=version,
                    )
                )
            continue
        tactic = attack.tactic(name.strip().lower())
        if tactic is not None:
            tactic_key: tuple[str | None, str | None, str | None] = (
                tactic.uid,
                None,
                None,
            )
            if tactic_key not in seen:
                seen.add(tactic_key)
                attacks.append(
                    AttackRef(
                        tactic=TacticRef(uid=tactic.uid, name=tactic.name),
                        version=version,
                    )
                )
            continue
        dropped += 1
    covered = {
        item.tactic.uid
        for item in attacks
        if item.tactic is not None
        and item.tactic.uid is not None
        and (item.technique is not None or item.sub_technique is not None)
    }
    attacks = [
        item
        for item in attacks
        if item.technique is not None
        or item.sub_technique is not None
        or item.tactic is None
        or item.tactic.uid is None
        or item.tactic.uid not in covered
    ]
    attacks.sort(
        key=lambda item: (
            (item.tactic.uid if item.tactic and item.tactic.uid else ""),
            (item.technique.uid if item.technique and item.technique.uid else ""),
            (
                item.sub_technique.uid
                if item.sub_technique and item.sub_technique.uid
                else ""
            ),
        )
    )
    return attacks, dropped


def _resolve_technique(
    attack: AttackDictionary, raw_id: str
) -> tuple[str, str, str | None, str | None, list[tuple[str, str]]] | None:
    """Resolve one technique tag to attack parts, or None when dropped.

    Returns ``(technique_uid, technique_name, sub_uid, sub_name,
    tactics)`` where tactics are ``(tactic_uid, display)`` pairs with
    the ``TA####`` tactic id. A sub-technique reports its parent as
    the technique; when the parent entry is missing, the sub-technique
    stands on its own.
    """
    canonical = normalize_id(raw_id)
    if canonical is None:
        return None
    entry = attack.resolve(canonical)
    if entry is None:
        return None
    tactics = [(tactic.uid, tactic.name) for tactic in entry.tactics]
    if entry.is_subtechnique and entry.parent is not None:
        parent = attack.get(entry.parent)
        if parent is None:
            return (entry.id, entry.name, None, None, tactics)
        parent_tactics = [(tactic.uid, tactic.name) for tactic in parent.tactics]
        return (
            parent.id,
            parent.name,
            entry.id,
            entry.name,
            parent_tactics or tactics,
        )
    return (entry.id, entry.name, None, None, tactics)


def build_finding(
    rule: CompiledRule,
    event: MatchedEvent,
    attack: AttackDictionary,
    attack_version: str,
) -> DetectionFinding:
    """Build the Detection Finding for one rule match."""
    uid = finding_uid(rule.rule_id, event.uid)
    severity_id = SEVERITY_IDS[rule.level]
    attacks, _ = attacks_for_tags(attack, rule.tags, attack_version)
    analytic = Analytic(
        name=rule.title,
        uid=rule.rule_id,
        desc=rule.description,
        type="Rule",
        type_id=1,
    )
    evidence = Evidence(
        uid=event.uid,
        actor=Actor(**event.actor) if isinstance(event.actor, dict) else None,
        process=Process(**event.process) if isinstance(event.process, dict) else None,
        src_endpoint=(
            Endpoint(**event.src_endpoint)
            if isinstance(event.src_endpoint, dict)
            else None
        ),
        dst_endpoint=(
            Endpoint(**event.dst_endpoint)
            if isinstance(event.dst_endpoint, dict)
            else None
        ),
        device=Device(**event.device) if isinstance(event.device, dict) else None,
        file=File(**event.file) if isinstance(event.file, dict) else None,
    )
    finding_info = FindingInfo(
        uid=uid,
        title=rule.title,
        desc=rule.description,
        analytic=analytic,
        attacks=attacks or None,
        related_events=[
            RelatedEvent(
                uid=event.uid,
                type_uid=event.class_uid * 100 + event.activity_id,
            )
        ],
        src_url=(
            "https://github.com/SigmaHQ/sigma/blob/"
            f"{SIGMA_RELEASE_TAG}/rules/windows/{rule.rel_path}"
            if rule.rel_path
            else None
        ),
    )
    unmapped: dict[str, Any] = {}
    if rule.author:
        unmapped["sigma_author"] = rule.author
    device = Device(**event.device) if isinstance(event.device, dict) else None
    return DetectionFinding(
        time=event.time,
        severity_id=severity_id,
        severity=SEVERITY_NAMES[severity_id],
        status="New",
        status_id=1,
        activity_id=1,
        start_time=event.time,
        end_time=event.time,
        metadata=Metadata(
            product=Product(name="Corvus", vendor_name="Ekos Cyber Labs"),
            log_name="sigma",
            uid=uid,
            # The finding carries the matched event's device context,
            # so the host profile-gated ``device`` attribute counts.
            profiles=["host"] if device is not None else None,
        ),
        device=device,
        finding_info=finding_info,
        evidences=[evidence],
        unmapped=unmapped,
    )
