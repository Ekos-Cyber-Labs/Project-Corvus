"""Deterministic correlation of Detection Findings into incidents.

Pure logic: no database, no CLI, no report. Input is OCSF 2004
Detection Findings (from replay detection now, from Wazuh alerts
later) plus the OCSF events they reference, keyed by uid (the same
shape ``SiemAdapter.query_events`` returns). Output is plain
JSON-serializable incident dicts (:class:`Incident`) that the
storage follow-up persists as they are.

Join rules:

- Entities are hosts (normalized, lowercase), users (normalized
  ``DOMAIN\\\\name``), source and destination IPs, and process lineage
  (``host:pid`` for a process and its parent, from the referenced
  events and the finding evidence context).
- Well-known machine and service identities (see
  :mod:`corvus.correlate.identities`) are kept as attributes but never
  join: one service account must not glue every alert on a host into
  one incident. Process lineage keys are host-scoped (``host:pid``),
  so equal pids on different hosts never join.
- Two findings join the same incident when they share a join key and
  the gap from the incident's last finding is at most the session gap
  (default 30 minutes). An incident never spans more than the max span
  (default 24 hours). Defaults come from :mod:`corvus.settings`.
- Cross-host joins happen only through a shared non-service user, or
  when a finding's remote IP is another host's device IP observed in
  the same window (lateral movement). Two findings on different hosts
  that merely share a remote IP (both talking to the same external
  address) do not join.
- Findings are processed in canonical ``(time, uid)`` order, so any
  arrival order yields the same incidents. Merging two incidents keeps
  the older key (``corr-<earliest finding uid>``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, TypedDict

from corvus.attack.dictionary import AttackDictionary, load_dictionary
from corvus.correlate.identities import is_service_identity
from corvus.correlate.severity import primary_of, severity_floor
from corvus.normalize.ocsf import (
    Authentication,
    DetectionFinding,
    OcsfEvent,
    canonicalize_host,
    canonicalize_ip,
    canonicalize_user,
)
from corvus.settings import Settings

__all__ = [
    "DEFAULT_AUTH_FAILURE_THRESHOLD",
    "DEFAULT_MAX_SPAN",
    "DEFAULT_SESSION_GAP",
    "Incident",
    "correlate_findings",
]


def _settings_default(name: str) -> int:
    """Return the int default of a Settings field (single source of truth)."""
    value = Settings.model_fields[name].default
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"Settings.{name} default must be an int")
    return value


#: Session gap default: mirrors ``Settings.correlation_session_gap_minutes``.
DEFAULT_SESSION_GAP = timedelta(
    minutes=_settings_default("correlation_session_gap_minutes")
)

#: Max span default: mirrors ``Settings.correlation_max_span_hours``.
DEFAULT_MAX_SPAN = timedelta(hours=_settings_default("correlation_max_span_hours"))

#: Auth failure threshold default: mirrors
#: ``Settings.correlation_auth_failure_threshold``.
DEFAULT_AUTH_FAILURE_THRESHOLD = _settings_default("correlation_auth_failure_threshold")

#: Score step per tactic beyond the first: it orders incidents with
#: equal floors by breadth. The step size is provisional and is
#: calibrated with the evaluation harness later.
SCORE_BREADTH_STEP = 0.1


class Incident(TypedDict):
    """One candidate incident, JSON-serializable as stored.

    Field names match the ``incidents`` table of migration
    ``0002_core_tables.sql`` plus the ``severity_factors`` column the
    storage follow-up adds. ``first_seen``/``last_seen`` are UTC epoch
    milliseconds; the follow-up converts them to ``timestamptz``.
    ``event_uids`` holds member finding uids plus the referenced event
    uids present in the events map.
    """

    correlation_key: str
    title: str
    entity_keys: dict[str, list[str]]
    techniques: list[str]
    event_uids: list[str]
    first_seen: int
    last_seen: int
    deterministic_score: float
    severity_floor: int
    severity_id: int
    severity_factors: dict[str, Any]


@dataclass
class _Signals:
    """Join-relevant signals extracted from one finding."""

    uid: str
    time: int
    severity_id: int
    hosts: frozenset[str]
    device_ips: frozenset[str]
    users: frozenset[str]
    service_users: frozenset[str]
    remote_ips: frozenset[str]
    proc_keys: frozenset[str]
    tactics: tuple[str, ...]
    primary_tactic: str | None
    techniques: tuple[str, ...]
    referenced_uids: frozenset[str]

    @property
    def join_keys(self) -> frozenset[str]:
        """Keys that can join this finding to an incident."""
        keys = {f"host:{host}" for host in self.hosts}
        keys |= {f"user:{user}" for user in self.users}
        keys |= {f"ip:{ip}" for ip in self.device_ips | self.remote_ips}
        keys |= {f"proc:{proc}" for proc in self.proc_keys}
        return frozenset(keys)


@dataclass
class _Cluster:
    """Findings joined so far, with the union of their signals."""

    key: str
    members: list[_Signals] = field(default_factory=list)
    first_seen: int = 0
    last_seen: int = 0
    keys: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    device_ips: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    service_users: set[str] = field(default_factory=set)
    remote_ips: set[str] = field(default_factory=set)
    proc_keys: set[str] = field(default_factory=set)
    referenced_uids: set[str] = field(default_factory=set)

    def add(self, signals: _Signals) -> None:
        """Add one finding's signals (caller keeps time order)."""
        self.members.append(signals)
        self.first_seen = min(self.first_seen, signals.time)
        self.last_seen = max(self.last_seen, signals.time)
        self.keys |= set(signals.join_keys)
        self.hosts |= set(signals.hosts)
        self.device_ips |= set(signals.device_ips)
        self.users |= set(signals.users)
        self.service_users |= set(signals.service_users)
        self.remote_ips |= set(signals.remote_ips)
        self.proc_keys |= set(signals.proc_keys)
        self.referenced_uids |= set(signals.referenced_uids)


def _attack_parts(
    finding: DetectionFinding, attack: AttackDictionary
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve a finding's ATT&CK attacks to tactic shortnames and technique ids.

    Technique ids resolve through ``revoked-by``; unresolvable
    (unknown, deprecated, revoked-without-replacement) technique ids
    are ignored, never guessed. Tactic-only attacks map their ``TA####``
    uid back to the dictionary shortname; a tactic uid the dictionary
    does not know raises instead of defaulting.
    """
    ta_to_short: dict[str, str] = {}
    for shortname in attack.tactic_order:
        tactic = attack.tactic(shortname)
        if tactic is not None and tactic.uid is not None:
            ta_to_short[tactic.uid] = shortname
    tactics: set[str] = set()
    techniques: set[str] = set()
    attacks = finding.finding_info.attacks if finding.finding_info else None
    for ref in attacks or []:
        stated: str | None = (
            ref.sub_technique.uid
            if ref.sub_technique and ref.sub_technique.uid
            else (ref.technique.uid if ref.technique else None)
        )
        entry = attack.resolve(stated) if stated else None
        if entry is not None:
            tactics.update(tactic.shortname for tactic in entry.tactics)
            techniques.add(entry.id)
            if entry.parent is not None:
                techniques.add(entry.parent)
            continue
        tactic_uid = ref.tactic.uid if ref.tactic else None
        if tactic_uid is None:
            continue
        short = ta_to_short.get(tactic_uid)
        if short is None:
            raise ValueError(
                f"finding {finding.metadata.uid} names tactic {tactic_uid} "
                "unknown to the ATT&CK dictionary"
            )
        tactics.add(short)
    return tuple(sorted(tactics)), tuple(sorted(techniques))


def _signals_for(
    finding: DetectionFinding,
    events: Mapping[str, OcsfEvent],
    attack: AttackDictionary,
) -> _Signals:
    """Extract one finding's join signals from evidence plus referenced events."""
    uid = finding.metadata.uid or ""
    if not uid:
        raise ValueError("a finding without a stable metadata.uid cannot correlate")
    hosts: set[str] = set()
    device_ips: set[str] = set()
    users: set[str] = set()
    service_users: set[str] = set()

    def add_user(raw_name: str | None, raw_domain: str | None) -> None:
        key = canonicalize_user(raw_name, raw_domain)
        if key is None:
            return
        if is_service_identity(key):
            service_users.add(key)
        else:
            users.add(key)

    remote_ips: set[str] = set()
    proc_keys: set[str] = set()

    def add_process(host: str | None, pid: object, parent_pid: object) -> None:
        if host is None:
            return
        if isinstance(pid, int):
            proc_keys.add(f"{host}:{pid}")
        if isinstance(parent_pid, int):
            proc_keys.add(f"{host}:{parent_pid}")

    for evidence in finding.evidences or []:
        host: str | None = None
        if evidence.device is not None:
            host = canonicalize_host(evidence.device.hostname)
            if host is not None:
                hosts.add(host)
            ip = canonicalize_ip(evidence.device.ip)
            if ip is not None:
                device_ips.add(ip)
        if evidence.actor is not None and evidence.actor.user is not None:
            add_user(evidence.actor.user.name, evidence.actor.user.domain)
        for endpoint in (evidence.src_endpoint, evidence.dst_endpoint):
            if endpoint is not None:
                ip = canonicalize_ip(endpoint.ip)
                if ip is not None:
                    remote_ips.add(ip)
        if evidence.process is not None:
            parent = evidence.process.parent_process
            add_process(
                host,
                evidence.process.pid,
                parent.pid if parent is not None else None,
            )

    referenced: set[str] = set()
    if finding.finding_info and finding.finding_info.related_events:
        for related in finding.finding_info.related_events:
            if related.uid:
                referenced.add(related.uid)
    for evidence in finding.evidences or []:
        if evidence.uid:
            referenced.add(evidence.uid)
    for ref_uid in sorted(referenced):
        event = events.get(ref_uid)
        if event is None:
            continue
        keys = event.entity_keys
        if keys.host is not None:
            hosts.add(keys.host)
        for ip in (keys.ip, keys.src_ip, keys.dst_ip):
            if ip is None:
                continue
            if ip == keys.ip:
                device_ips.add(ip)
            else:
                remote_ips.add(ip)
        if keys.user is not None:
            if is_service_identity(keys.user):
                service_users.add(keys.user)
            else:
                users.add(keys.user)
        process = getattr(event, "process", None)
        if process is not None:
            parent = getattr(process, "parent_process", None)
            add_process(
                keys.host,
                getattr(process, "pid", None),
                getattr(parent, "pid", None) if parent is not None else None,
            )

    tactics, techniques = _attack_parts(finding, attack)
    return _Signals(
        uid=uid,
        time=finding.time,
        severity_id=finding.severity_id,
        hosts=frozenset(hosts),
        device_ips=frozenset(device_ips),
        users=frozenset(users),
        service_users=frozenset(service_users),
        remote_ips=frozenset(remote_ips),
        proc_keys=frozenset(proc_keys),
        tactics=tactics,
        primary_tactic=primary_of(tactics, attack.tactic_order),
        techniques=techniques,
        referenced_uids=frozenset(referenced),
    )


def _cross_host_ok(signals: _Signals, cluster: _Cluster) -> bool:
    """Check the cross-host rule for adding one finding to a cluster.

    Findings whose host sets are both known and disjoint join only
    through a shared non-service user, or when an endpoint IP on one
    side is a device IP on the other (lateral movement). A remote IP
    that is remote on both sides never joins across hosts.
    """
    if not signals.hosts or not cluster.hosts:
        return True
    if signals.hosts & cluster.hosts:
        return True
    if signals.users & cluster.users:
        return True
    shared_ips = (signals.device_ips | signals.remote_ips) & (
        cluster.device_ips | cluster.remote_ips
    )
    return bool(shared_ips & (signals.device_ips | cluster.device_ips))


def _auth_outcome(event: Authentication) -> str | None:
    """Classify an Authentication event as success, failure, or unknown."""
    if event.status_id == 1:
        return "success"
    if event.status_id == 2:
        return "failure"
    status = (event.status or "").strip().lower()
    if status == "success":
        return "success"
    if status in ("failure", "failed"):
        return "failure"
    return None


def _success_detail(
    cluster: _Cluster,
    events: Mapping[str, OcsfEvent],
    threshold: int,
    window_start_ms: int,
) -> dict[str, Any]:
    """Check factor 4 over every matching Authentication event in the map.

    Detection rules rarely match each failed logon, so referenced
    events alone miss the pattern: every Authentication event in
    ``events`` counts when its target (entity user or host) matches a
    user or host of the incident and its time falls inside
    ``[window_start_ms, last_seen]``. Returns whether a success follows
    at least ``threshold`` failures against the same target user/host,
    with the earliest firing success as the witness.
    """
    failures: dict[tuple[str | None, str | None], list[int]] = {}
    successes: dict[tuple[str | None, str | None], list[tuple[int, str]]] = {}
    for ref_uid in sorted(events):
        event = events[ref_uid]
        if not isinstance(event, Authentication):
            continue
        if event.time < window_start_ms or event.time > cluster.last_seen:
            continue
        target_user = event.entity_keys.user
        target_host = event.entity_keys.host
        if target_user not in cluster.users and target_host not in cluster.hosts:
            continue
        outcome = _auth_outcome(event)
        if outcome is None:
            continue
        target = (target_user, target_host)
        if outcome == "failure":
            failures.setdefault(target, []).append(event.time)
        else:
            successes.setdefault(target, []).append((event.time, ref_uid))
    best: tuple[int, str, str | None, str | None, int] | None = None
    for target, wins in successes.items():
        prior = sorted(failures.get(target, []))
        for when, ref_uid in sorted(wins):
            before = sum(1 for moment in prior if moment <= when)
            if before >= threshold:
                candidate = (when, ref_uid, target[0], target[1], before)
                if best is None or (candidate[0], candidate[1]) < (
                    best[0],
                    best[1],
                ):
                    best = candidate
    if best is None:
        return {"fired": False}
    return {
        "fired": True,
        "target_user": best[2],
        "target_host": best[3],
        "failures_before": best[4],
        "success_uid": best[1],
    }


def _build_incident(
    cluster: _Cluster,
    attack: AttackDictionary,
    events: Mapping[str, OcsfEvent],
    auth_failure_threshold: int,
    gap_ms: int,
) -> Incident:
    """Render one cluster as a plain JSON-serializable incident dict."""
    tactics = sorted({short for member in cluster.members for short in member.tactics})
    primaries = sorted(
        {
            member.primary_tactic
            for member in cluster.members
            if member.primary_tactic is not None
        }
    )
    techniques = sorted(
        {tech for member in cluster.members for tech in member.techniques}
    )
    max_severity = max(member.severity_id for member in cluster.members)
    detail = _success_detail(
        cluster, events, auth_failure_threshold, cluster.first_seen - gap_ms
    )
    floor, factors = severity_floor(
        tactics, primaries, list(attack.tactic_order), max_severity, detail["fired"]
    )
    factor_4 = factors["factor_4_success_vs_attempt"]
    factors["factor_4_success_vs_attempt"] = {**factor_4, **detail}
    breadth = len(primaries)
    score = round(float(floor) + SCORE_BREADTH_STEP * max(breadth - 1, 0), 2)
    earliest = min(cluster.members, key=lambda member: (member.time, member.uid))
    most_advanced = factors["factor_1_attack_stage"]["most_advanced_tactic"]
    if most_advanced is not None:
        display = attack.tactic_names.get(str(most_advanced), str(most_advanced))
    else:
        display = "Unclassified"
    primary = sorted(earliest.hosts)[0] if earliest.hosts else "unknown host"
    count = len(cluster.members)
    title = f"{display} on {primary} ({count} finding{'s' if count != 1 else ''})"
    return Incident(
        correlation_key=cluster.key,
        title=title,
        entity_keys={
            "hosts": sorted(cluster.hosts),
            "users": sorted(cluster.users),
            "service_users": sorted(cluster.service_users),
            "ips": sorted(cluster.device_ips | cluster.remote_ips),
            "processes": sorted(cluster.proc_keys),
        },
        techniques=techniques,
        event_uids=sorted(
            {member.uid for member in cluster.members}
            | (cluster.referenced_uids & set(events))
        ),
        first_seen=cluster.first_seen,
        last_seen=cluster.last_seen,
        deterministic_score=score,
        severity_floor=floor,
        severity_id=floor,
        severity_factors=factors,
    )


def correlate_findings(
    findings: list[DetectionFinding],
    events_by_uid: Mapping[str, OcsfEvent] | None = None,
    attack: AttackDictionary | None = None,
    session_gap: timedelta = DEFAULT_SESSION_GAP,
    max_span: timedelta = DEFAULT_MAX_SPAN,
    auth_failure_threshold: int = DEFAULT_AUTH_FAILURE_THRESHOLD,
) -> list[Incident]:
    """Correlate findings into candidate incidents, deterministically.

    ``findings`` arrive in any order; they are processed in canonical
    ``(time, uid)`` order, so shuffling the input changes neither the
    incidents nor their ``correlation_key`` values. ``events_by_uid``
    holds the referenced OCSF events (process lineage) plus the
    Authentication events the success-vs-attempt factor needs: rules
    rarely match each failed logon, so the caller passes those
    authentication attempts along with the referenced events (the
    storage follow-up queries them from the SIEM) and factor 4
    considers every one whose target matches the incident inside
    ``[first_seen - session gap, last_seen]``. Findings without
    referenced events correlate on their evidence context alone.
    """
    dictionary = attack if attack is not None else load_dictionary()
    events: Mapping[str, OcsfEvent] = events_by_uid or {}
    gap_ms = int(session_gap.total_seconds() * 1000)
    span_ms = int(max_span.total_seconds() * 1000)
    ordered = sorted(
        (_signals_for(finding, events, dictionary) for finding in findings),
        key=lambda signals: (signals.time, signals.uid),
    )
    clusters: list[_Cluster] = []
    for signals in ordered:
        candidates = [
            cluster
            for cluster in clusters
            if cluster.keys & signals.join_keys
            and signals.time - cluster.last_seen <= gap_ms
            and signals.time - cluster.first_seen <= span_ms
            and _cross_host_ok(signals, cluster)
        ]
        if not candidates:
            cluster = _Cluster(key=f"corr-{signals.uid}")
            cluster.first_seen = signals.time
            cluster.add(signals)
            clusters.append(cluster)
        elif len(candidates) == 1:
            candidates[0].add(signals)
        else:
            keeper = min(candidates, key=lambda item: (item.first_seen, item.key))
            others = [item for item in candidates if item is not keeper]
            for other in others:
                for member in sorted(
                    other.members, key=lambda item: (item.time, item.uid)
                ):
                    keeper.add(member)
                clusters.remove(other)
            keeper.add(signals)
    incidents = [
        _build_incident(cluster, dictionary, events, auth_failure_threshold, gap_ms)
        for cluster in clusters
    ]
    return sorted(
        incidents, key=lambda item: (item["first_seen"], item["correlation_key"])
    )
