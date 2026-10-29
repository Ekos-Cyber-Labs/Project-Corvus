"""Tests for deterministic correlation (corvus/correlate).

Fixture-first: every finding below is hand-written (RFC 5737 IPs,
``example.com`` domains); the ATT&CK dictionary is a minimal
hand-built compact mapping except for the stage-coverage test, which
loads the real built dictionary and skips when it has not been built.
"""

from __future__ import annotations

import json
import random
from datetime import timedelta
from pathlib import Path

import pytest

from corvus.attack import AttackDictionary, load_dictionary
from corvus.correlate import (
    STAGE_LEVELS,
    check_stage_coverage,
    correlate_findings,
    is_service_identity,
)
from corvus.normalize.ocsf import (
    Actor,
    AttackRef,
    Authentication,
    DetectionFinding,
    Device,
    Endpoint,
    Evidence,
    FindingInfo,
    Metadata,
    OcsfEvent,
    Process,
    ProcessActivity,
    Product,
    RelatedEvent,
    TacticRef,
    TechniqueRef,
    User,
)

#: Base event time (2023-11-14T22:13:20Z), safely above the 2000 floor.
BASE_MS = 1_700_000_000_000
MINUTE_MS = 60_000

_FIXTURE_COMPACT: dict[str, object] = {
    "tactics": {
        "reconnaissance": {"name": "Reconnaissance", "id": "TA0043"},
        "discovery": {"name": "Discovery", "id": "TA0007"},
        "execution": {"name": "Execution", "id": "TA0002"},
        "persistence": {"name": "Persistence", "id": "TA0003"},
        "privilege-escalation": {"name": "Privilege Escalation", "id": "TA0004"},
        "credential-access": {"name": "Credential Access", "id": "TA0006"},
        "lateral-movement": {"name": "Lateral Movement", "id": "TA0008"},
        "command-and-control": {
            "name": "Command and Control",
            "id": "TA0011",
        },
    },
    "tactic_order": [
        "reconnaissance",
        "discovery",
        "execution",
        "credential-access",
        "lateral-movement",
        "command-and-control",
        "persistence",
        "privilege-escalation",
    ],
    "techniques": {
        "T1595": {
            "name": "Active Scanning",
            "tactics": ["reconnaissance"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
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
        "T1059.001": {
            "name": "PowerShell",
            "tactics": ["execution"],
            "is_subtechnique": True,
            "parent": "T1059",
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
        "T1053": {
            "name": "Scheduled Task/Job",
            "tactics": ["execution", "persistence", "privilege-escalation"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactics": ["credential-access"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
        "T1021": {
            "name": "Remote Services",
            "tactics": ["lateral-movement"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactics": ["command-and-control"],
            "is_subtechnique": False,
            "parent": None,
            "deprecated": False,
            "revoked": False,
            "revoked_by": None,
        },
    },
}

_TECHNIQUE_TACTIC = {
    "T1595": ("TA0043", "Reconnaissance"),
    "T1083": ("TA0007", "Discovery"),
    "T1059": ("TA0002", "Execution"),
    "T1053": ("TA0002", "Execution"),
    "T1003": ("TA0006", "Credential Access"),
    "T1021": ("TA0008", "Lateral Movement"),
    "T1071": ("TA0011", "Command and Control"),
}


def _attack() -> AttackDictionary:
    return AttackDictionary.from_compact(_FIXTURE_COMPACT)


def _attack_ref(technique_id: str) -> AttackRef:
    tactic_uid, tactic_name = _TECHNIQUE_TACTIC[technique_id]
    return AttackRef(
        tactic=TacticRef(uid=tactic_uid, name=tactic_name),
        technique=TechniqueRef(uid=technique_id, name=technique_id),
        version="v20.0",
    )


def _metadata(uid: str) -> Metadata:
    return Metadata(
        product=Product(name="Corvus", vendor_name="Ekos Cyber Labs"),
        log_name="sigma",
        uid=uid,
    )


def make_finding(
    uid: str,
    minutes: float,
    techniques: list[str] | tuple[str, ...] = (),
    severity_id: int = 3,
    host: str | None = "web01",
    user: str | None = "alice",
    domain: str | None = "example",
    device_ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    pid: int | None = None,
    parent_pid: int | None = None,
    evidence_uid: str | None = None,
    related_uids: list[str] | None = None,
) -> DetectionFinding:
    """Build one hand-written Detection Finding with evidence context."""
    actor = Actor(user=User(name=user, domain=domain)) if user is not None else None
    device = Device(hostname=host, ip=device_ip) if host is not None else None
    process = None
    if pid is not None:
        process = Process(
            pid=pid,
            parent_process=Process(pid=parent_pid) if parent_pid is not None else None,
        )
    ref_uid = evidence_uid or f"ev-{uid}"
    evidence = Evidence(
        uid=ref_uid,
        actor=actor,
        device=device,
        process=process,
        src_endpoint=Endpoint(ip=src_ip) if src_ip else None,
        dst_endpoint=Endpoint(ip=dst_ip) if dst_ip else None,
    )
    attacks = [_attack_ref(tid) for tid in techniques]
    captions = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
    return DetectionFinding(
        time=BASE_MS + round(minutes * MINUTE_MS),
        severity_id=severity_id,
        severity=captions.get(severity_id, "Other"),
        status="New",
        status_id=1,
        metadata=_metadata(uid),
        device=device,
        finding_info=FindingInfo(
            uid=uid,
            title=f"rule {uid}",
            attacks=attacks or None,
            related_events=[RelatedEvent(uid=r) for r in (related_uids or [ref_uid])],
        ),
        evidences=[evidence],
    )


def make_auth(
    uid: str,
    minutes: float,
    user: str = "alice",
    domain: str = "example",
    host: str = "web01",
    success: bool = False,
) -> Authentication:
    """Build one hand-written Authentication event."""
    actor_user = User(name=user, domain=domain)
    return Authentication(
        time=BASE_MS + round(minutes * MINUTE_MS),
        severity_id=1,
        metadata=_metadata(uid),
        device=Device(hostname=host),
        actor=Actor(user=actor_user),
        user=actor_user,
        status="Success" if success else "Failure",
        status_id=1 if success else 2,
    )


def make_process(
    uid: str, minutes: float, host: str, pid: int, parent_pid: int
) -> ProcessActivity:
    """Build one hand-written Process Activity event."""
    return ProcessActivity(
        time=BASE_MS + round(minutes * MINUTE_MS),
        severity_id=1,
        metadata=_metadata(uid),
        device=Device(hostname=host),
        process=Process(pid=pid, parent_process=Process(pid=parent_pid)),
    )


def test_service_identities_never_join() -> None:
    assert is_service_identity(None)
    assert is_service_identity("")
    assert is_service_identity("system")
    assert is_service_identity("nt authority\\system")
    assert is_service_identity("NT AUTHORITY\\LOCAL SERVICE")
    assert is_service_identity("nt authority\\network service")
    assert is_service_identity("anonymous logon")
    assert is_service_identity("example\\web01$")
    assert is_service_identity("web01$")
    assert not is_service_identity("example\\alice")
    assert not is_service_identity("alice")
    assert not is_service_identity("example\\svc-backup")


def test_service_account_does_not_glue_hosts() -> None:
    attack = _attack()
    first = make_finding(
        "f1", 0, ["T1083"], host="web01", user="SYSTEM", domain="NT AUTHORITY"
    )
    second = make_finding(
        "f2", 5, ["T1083"], host="web02", user="SYSTEM", domain="NT AUTHORITY"
    )
    incidents = correlate_findings([first, second], {}, attack)
    assert len(incidents) == 2
    assert incidents[0]["entity_keys"]["service_users"] == ["nt authority\\system"]
    assert incidents[0]["entity_keys"]["users"] == []


def test_shared_human_user_joins_across_hosts() -> None:
    attack = _attack()
    first = make_finding("f1", 0, ["T1083"], host="web01", user="alice")
    second = make_finding("f2", 5, ["T1059"], host="web02", user="alice")
    incidents = correlate_findings([first, second], {}, attack)
    assert len(incidents) == 1
    assert incidents[0]["entity_keys"]["hosts"] == ["web01", "web02"]
    assert incidents[0]["entity_keys"]["users"] == ["example\\alice"]


def test_factor_1_attack_stage() -> None:
    attack = _attack()
    cases = [("T1595", 2), ("T1083", 2), ("T1059", 3), ("T1003", 4)]
    for index, (technique, expected) in enumerate(cases):
        finding = make_finding(
            f"stage-{index}", 0, [technique], host=f"stage-host-{index}"
        )
        (incident,) = correlate_findings([finding], {}, attack)
        assert incident["severity_floor"] == expected, technique
        assert incident["severity_id"] == expected, technique
        factors = incident["severity_factors"]["factor_1_attack_stage"]
        assert factors["level"] == expected
        assert factors["most_advanced_tactic"] is not None


def test_factor_2_breadth_bonus_and_critical_gate() -> None:
    attack = _attack()
    pair = [
        make_finding("b1", 0, ["T1059"]),
        make_finding("b2", 5, ["T1083"]),
    ]
    (incident,) = correlate_findings(pair, {}, attack)
    assert incident["severity_floor"] == 3
    assert incident["severity_factors"]["factor_2_breadth"] == {
        "primary_tactics": ["discovery", "execution"],
        "distinct_tactics": 2,
        "added_level": False,
        "contribution": "adds nothing",
    }

    trio = pair + [make_finding("b3", 10, ["T1595"])]
    (incident,) = correlate_findings(trio, {}, attack)
    assert incident["severity_floor"] == 4
    assert incident["severity_factors"]["factor_2_breadth"]["added_level"] is True
    assert incident["deterministic_score"] == 4.2

    high_trio = [
        make_finding("h1", 0, ["T1003"]),
        make_finding("h2", 5, ["T1059"]),
        make_finding("h3", 10, ["T1083"]),
    ]
    (incident,) = correlate_findings(high_trio, {}, attack)
    assert incident["severity_floor"] == 4
    assert incident["severity_factors"]["factor_2_breadth"] == {
        "primary_tactics": ["credential-access", "discovery", "execution"],
        "distinct_tactics": 3,
        "added_level": True,
        "contribution": "adds one level",
    }

    quad = high_trio + [make_finding("h4", 15, ["T1021"])]
    (incident,) = correlate_findings(quad, {}, attack)
    assert incident["severity_floor"] == 5
    assert incident["severity_id"] == 5


def test_single_multi_tactic_finding_gets_no_breadth_bonus() -> None:
    attack = _attack()
    (incident,) = correlate_findings(
        [make_finding("sched-1", 0, ["T1053"])], {}, attack
    )
    factor_1 = incident["severity_factors"]["factor_1_attack_stage"]
    assert factor_1["tactics"] == [
        "execution",
        "persistence",
        "privilege-escalation",
    ]
    factor_2 = incident["severity_factors"]["factor_2_breadth"]
    assert factor_2["primary_tactics"] == ["privilege-escalation"]
    assert factor_2["distinct_tactics"] == 1
    assert factor_2["added_level"] is False
    assert incident["severity_floor"] == 3
    assert incident["severity_id"] == 3


def test_three_distinct_primaries_get_bonus() -> None:
    attack = _attack()
    findings = [
        make_finding("v1", 0, ["T1053"]),
        make_finding("v2", 5, ["T1083"]),
        make_finding("v3", 10, ["T1595"]),
    ]
    (incident,) = correlate_findings(findings, {}, attack)
    factor_2 = incident["severity_factors"]["factor_2_breadth"]
    assert factor_2["primary_tactics"] == [
        "discovery",
        "privilege-escalation",
        "reconnaissance",
    ]
    assert factor_2["added_level"] is True
    assert incident["severity_floor"] == 4


def _auth_chain(
    failures: int, success: bool
) -> tuple[list[DetectionFinding], dict[str, OcsfEvent]]:
    findings: list[DetectionFinding] = []
    events: dict[str, OcsfEvent] = {}
    for index in range(failures):
        uid = f"auth-fail-{index}"
        events[uid] = make_auth(uid, index, success=False)
        findings.append(
            make_finding(
                f"f-fail-{index}",
                index,
                ["T1083"],
                severity_id=2,
                evidence_uid=uid,
                related_uids=[uid],
            )
        )
    if success:
        events["auth-ok"] = make_auth("auth-ok", failures, success=True)
        findings.append(
            make_finding(
                "f-ok",
                failures,
                ["T1059"],
                severity_id=3,
                evidence_uid="auth-ok",
                related_uids=["auth-ok"],
            )
        )
    return findings, events


def test_factor_4_success_after_failures_sets_high() -> None:
    attack = _attack()
    findings, events = _auth_chain(failures=3, success=True)
    (incident,) = correlate_findings(findings, events, attack)
    assert incident["severity_floor"] == 4
    assert incident["severity_id"] == 4
    factor_4 = incident["severity_factors"]["factor_4_success_vs_attempt"]
    assert factor_4["fired"] is True
    assert factor_4["target_user"] == "example\\alice"
    assert factor_4["target_host"] == "web01"
    assert factor_4["failures_before"] == 3
    assert factor_4["success_uid"] == "auth-ok"


def test_factor_4_failures_alone_add_nothing() -> None:
    attack = _attack()
    findings, events = _auth_chain(failures=3, success=False)
    (incident,) = correlate_findings(findings, events, attack)
    assert incident["severity_floor"] == 2
    assert incident["severity_factors"]["factor_4_success_vs_attempt"]["fired"] is False


def test_factor_4_needs_enough_failures() -> None:
    attack = _attack()
    findings, events = _auth_chain(failures=2, success=True)
    (incident,) = correlate_findings(findings, events, attack)
    assert incident["severity_floor"] == 3
    assert incident["severity_factors"]["factor_4_success_vs_attempt"]["fired"] is False


def test_factor_4_sees_unreferenced_authentication_events() -> None:
    attack = _attack()
    findings = [
        make_finding("w1", 0, ["T1083"], severity_id=3),
        make_finding("w2", 5, ["T1083"], severity_id=3),
    ]
    events: dict[str, OcsfEvent] = {
        f"auth-fail-{index}": make_auth(f"auth-fail-{index}", index, success=False)
        for index in range(3)
    }
    events["auth-ok"] = make_auth("auth-ok", 4, success=True)
    (incident,) = correlate_findings(findings, events, attack)
    assert incident["event_uids"] == ["w1", "w2"]
    assert incident["severity_floor"] == 4
    factor_4 = incident["severity_factors"]["factor_4_success_vs_attempt"]
    assert factor_4["fired"] is True
    assert factor_4["target_user"] == "example\\alice"
    assert factor_4["target_host"] == "web01"
    assert factor_4["failures_before"] == 3
    assert factor_4["success_uid"] == "auth-ok"


def test_factor_4_ignores_attempts_outside_the_window() -> None:
    attack = _attack()
    findings = [
        make_finding("e1", 0, ["T1083"], severity_id=3),
        make_finding("e2", 5, ["T1083"], severity_id=3),
    ]
    events: dict[str, OcsfEvent] = {
        f"old-fail-{index}": make_auth(f"old-fail-{index}", -40 + index, success=False)
        for index in range(3)
    }
    events["auth-ok"] = make_auth("auth-ok", 4, success=True)
    (incident,) = correlate_findings(findings, events, attack)
    assert incident["severity_floor"] == 2
    assert incident["severity_factors"]["factor_4_success_vs_attempt"]["fired"] is False


def test_quiet_single_tactic_incidents_stay_low() -> None:
    attack = _attack()
    findings = [
        make_finding("q1", 0, ["T1059"], severity_id=1),
        make_finding("q2", 5, ["T1059"], severity_id=2),
    ]
    (incident,) = correlate_findings(findings, {}, attack)
    assert incident["severity_floor"] == 2
    assert incident["severity_id"] == 2
    assert incident["severity_factors"]["level_cap"]["applied"] is True


def test_cross_host_lateral_join() -> None:
    attack = _attack()
    first = make_finding(
        "l1",
        0,
        ["T1021"],
        host="web01",
        user="alice",
        device_ip="192.0.2.10",
        dst_ip="192.0.2.20",
    )
    second = make_finding(
        "l2", 5, ["T1059"], host="web02", user="bob", device_ip="192.0.2.20"
    )
    incidents = correlate_findings([first, second], {}, attack)
    assert len(incidents) == 1
    assert incidents[0]["entity_keys"]["hosts"] == ["web01", "web02"]


def test_shared_remote_ip_alone_does_not_join_hosts() -> None:
    attack = _attack()
    first = make_finding(
        "r1", 0, ["T1071"], host="web01", user="alice", dst_ip="203.0.113.5"
    )
    second = make_finding(
        "r2", 5, ["T1071"], host="web02", user="bob", dst_ip="203.0.113.5"
    )
    assert len(correlate_findings([first, second], {}, attack)) == 2


def test_process_lineage_is_host_scoped() -> None:
    attack = _attack()
    events: dict[str, OcsfEvent] = {
        "proc-1": make_process("proc-1", 0, "web01", 1234, 567),
        "proc-2": make_process("proc-2", 5, "web01", 2345, 1234),
    }
    first = make_finding("p1", 0, ["T1059"], related_uids=["proc-1"])
    second = make_finding("p2", 5, ["T1059"], related_uids=["proc-2"])
    (incident,) = correlate_findings([first, second], events, attack)
    assert incident["entity_keys"]["processes"] == [
        "web01:1234",
        "web01:2345",
        "web01:567",
    ]
    assert incident["event_uids"] == ["p1", "p2", "proc-1", "proc-2"]

    other: dict[str, OcsfEvent] = {
        "proc-3": make_process("proc-3", 0, "web02", 1234, 567),
    }
    third = make_finding(
        "p3", 1, ["T1059"], host="web02", user="bob", related_uids=["proc-3"]
    )
    assert len(correlate_findings([first, third], other, attack)) == 2


def test_session_gap_edge() -> None:
    attack = _attack()
    first = make_finding("g1", 0, ["T1083"])
    inside = make_finding("g2", 30, ["T1083"])
    assert len(correlate_findings([first, inside], {}, attack)) == 1
    outside = make_finding("g3", 0, ["T1083"], host="gap-host")
    later = make_finding("g4", 30 + 1 / MINUTE_MS, ["T1083"], host="gap-host")
    assert len(correlate_findings([outside, later], {}, attack)) == 2


def test_max_span_edge() -> None:
    attack = _attack()
    wide_gap = timedelta(hours=25)
    first = make_finding("s1", 0, ["T1083"], host="span-host")
    inside = make_finding("s2", 24 * 60, ["T1083"], host="span-host")
    assert (
        len(correlate_findings([first, inside], {}, attack, session_gap=wide_gap)) == 1
    )
    later = make_finding("s3", 24 * 60 + 1 / MINUTE_MS, ["T1083"], host="span-host-2")
    earlier = make_finding("s4", 0, ["T1083"], host="span-host-2")
    assert (
        len(correlate_findings([earlier, later], {}, attack, session_gap=wide_gap)) == 2
    )


def test_merge_keeps_older_key() -> None:
    attack = _attack()
    first = make_finding("z1", 0, ["T1083"], host="web01", user="alice")
    second = make_finding("a2", 5, ["T1059"], host="web02", user="bob")
    bridge = make_finding("m3", 10, ["T1021"], host="web02", user="alice")
    assert len(correlate_findings([first, second], {}, attack)) == 2
    (incident,) = correlate_findings([first, second, bridge], {}, attack)
    assert incident["correlation_key"] == "corr-z1"
    assert incident["event_uids"] == ["a2", "m3", "z1"]
    assert incident["first_seen"] == BASE_MS
    assert incident["last_seen"] == BASE_MS + 10 * MINUTE_MS


def test_shuffled_order_gives_same_incidents() -> None:
    attack = _attack()
    findings = [
        make_finding("o1", 0, ["T1083"], host="web01", user="alice"),
        make_finding("o2", 5, ["T1059"], host="web01", user="alice"),
        make_finding("o3", 30, ["T1003"], host="web01", user="alice"),
        make_finding("o4", 2, ["T1083"], host="web02", user="bob"),
        make_finding("o5", 7, ["T1059"], host="web02", user="bob"),
        make_finding("o6", 200, ["T1595"], host="web03", user="carol"),
    ]
    reference = correlate_findings(list(findings), {}, attack)
    assert len(reference) == 3
    orders = [list(reversed(findings))]
    rng = random.Random(42)
    for _ in range(5):
        shuffled = list(findings)
        rng.shuffle(shuffled)
        orders.append(shuffled)
    for order in orders:
        assert correlate_findings(order, {}, attack) == reference
    assert [item["correlation_key"] for item in reference] == [
        "corr-o1",
        "corr-o4",
        "corr-o6",
    ]


def test_incident_shape_is_serializable() -> None:
    attack = _attack()
    findings, events = _auth_chain(failures=3, success=True)
    (incident,) = correlate_findings(findings, events, attack)
    assert set(incident) == {
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
    assert set(incident["entity_keys"]) == {
        "hosts",
        "users",
        "service_users",
        "ips",
        "processes",
    }
    assert incident["techniques"] == ["T1059", "T1083"]
    assert incident["severity_id"] == incident["severity_floor"]
    assert isinstance(incident["deterministic_score"], float)
    assert incident["entity_keys"]["hosts"] == ["web01"]
    assert incident["entity_keys"]["users"] == ["example\\alice"]
    assert incident["title"] == "Execution on web01 (4 findings)"
    json.dumps(incident)


def test_unknown_tactic_uid_raises() -> None:
    attack = _attack()
    finding = make_finding("u1", 0, [], host="web01")
    assert finding.finding_info is not None
    finding.finding_info.attacks = [
        AttackRef(tactic=TacticRef(uid="TA9999", name="Future"), version="v20.0")
    ]
    with pytest.raises(ValueError, match="TA9999"):
        correlate_findings([finding], {}, attack)


def test_stage_coverage_of_loaded_dictionary() -> None:
    target = Path("data/attack/enterprise.json")
    if not target.is_file():
        pytest.skip("compact ATT&CK dictionary not built")
    dictionary = load_dictionary()
    assert len(dictionary.tactic_order) == 15
    assert check_stage_coverage(list(dictionary.tactic_order)) == []
    assert set(STAGE_LEVELS) == set(dictionary.tactic_order)
