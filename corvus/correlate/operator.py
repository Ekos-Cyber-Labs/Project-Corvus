"""Operator (administrative) sessions: mark findings, never join them to attacks.

The operator lists the networks they administer from in
``CORVUS_OPERATOR_SOURCES`` (comma or space separated CIDRs or single
addresses, kept outside the repository). Marking is deterministic:

- A successful Authentication event whose source IP falls inside a
  listed network opens an operator session for its ``(host, user)``.
  A session extends while marked activity for that pair keeps arriving
  within the session gap (the same gap correlation uses).
- A successful Authentication for the same ``(host, user)`` from a
  source IP outside the list, inside ``[session start - gap, session
  end + gap]``, makes the session ambiguous: nothing in it is marked.
  Authentications without a source IP (PAM session records, ``su``,
  console) are neutral: they neither open nor void a session.
- Inside a session, a finding is marked only when it names exactly that
  one host and that one non-service user, every remote IP it names is
  inside a listed network, every technique it maps to is a session
  technique (:data:`SESSION_TECHNIQUES`, sub-techniques included) or it
  maps to none, and neither the finding nor any event it references
  carries an injection signal (:func:`corvus.guardrails.injection.detect`).

Marking never deletes anything: marked findings still form incidents,
in their own join-key space (see :mod:`corvus.correlate.correlate`), so
an attack never absorbs administration and administration never hides
an attack. The networks are an operator input, never model output.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from corvus.normalize.ocsf import Authentication, DetectionFinding, OcsfEvent

__all__ = [
    "MIN_PREFIX_V4",
    "MIN_PREFIX_V6",
    "OPERATOR_SOURCES_ENV",
    "SESSION_TECHNIQUES",
    "OperatorNetwork",
    "SessionCandidate",
    "mark_operator_findings",
    "operator_sources_from_env",
    "parse_operator_sources",
]

#: Environment variable holding the operator networks.
OPERATOR_SOURCES_ENV = "CORVUS_OPERATOR_SOURCES"

#: Techniques an administrative session is made of (D33): Valid
#: Accounts, Remote Services and Abuse Elevation Control Mechanism
#: (sudo). Sub-techniques count through their parent id.
SESSION_TECHNIQUES = frozenset({"T1078", "T1021", "T1548"})

#: Broadest networks accepted: a wider list would mark half the internet.
MIN_PREFIX_V4 = 16
MIN_PREFIX_V6 = 48

OperatorNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_operator_sources(text: str | None) -> tuple[OperatorNetwork, ...]:
    """Parse the operator network list; raise ``ValueError`` on any bad entry.

    Empty or unset yields ``()`` (marking off). Entries are CIDRs or
    single addresses; host bits must be zero and the prefix must be at
    least :data:`MIN_PREFIX_V4` (IPv4) or :data:`MIN_PREFIX_V6` (IPv6).
    The message names the position of a bad entry, never its value.
    """
    if text is None or not text.strip():
        return ()
    networks: list[OperatorNetwork] = []
    for position, entry in enumerate(re.split(r"[\s,]+", text.strip()), start=1):
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError:
            raise ValueError(
                f"{OPERATOR_SOURCES_ENV} entry {position} is not a network"
                " (CIDR with zero host bits, or one address)"
            ) from None
        floor = MIN_PREFIX_V4 if network.version == 4 else MIN_PREFIX_V6
        if network.prefixlen < floor:
            raise ValueError(
                f"{OPERATOR_SOURCES_ENV} entry {position} is broader than"
                f" /{floor}: list the networks you administer from"
            )
        if network not in networks:
            networks.append(network)
    return tuple(networks)


def operator_sources_from_env() -> tuple[OperatorNetwork, ...]:
    """Read :data:`OPERATOR_SOURCES_ENV`; raise ``ValueError`` when malformed."""
    return parse_operator_sources(os.environ.get(OPERATOR_SOURCES_ENV))


def _inside(ip: str | None, networks: Sequence[OperatorNetwork]) -> bool:
    if ip is None:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


@dataclass(frozen=True)
class SessionCandidate:
    """The join signals of one finding that marking needs."""

    uid: str
    time: int
    hosts: frozenset[str]
    users: frozenset[str]
    remote_ips: frozenset[str]
    techniques: tuple[str, ...]
    referenced_uids: frozenset[str]


@dataclass
class _Session:
    """One operator session for a ``(host, user)`` pair."""

    start: int
    last: int
    login_uid: str
    members: list[SessionCandidate] = field(default_factory=list)


def _session_techniques_only(techniques: Iterable[str]) -> bool:
    return all(tech.split(".", 1)[0] in SESSION_TECHNIQUES for tech in techniques)


def _has_injection(
    finding: DetectionFinding | None,
    referenced: Iterable[str],
    events: Mapping[str, OcsfEvent],
) -> bool:
    """True when the finding or a referenced event carries an injection signal.

    A detector failure counts as a signal: marking fails closed.
    """
    from corvus.guardrails.injection import detect

    subjects: list[Any] = [finding] if finding is not None else []
    subjects.extend(events[uid] for uid in sorted(referenced) if uid in events)
    for subject in subjects:
        try:
            if detect(subject):
                return True
        except Exception:
            return True
    return False


def _logins(
    events: Mapping[str, OcsfEvent], networks: Sequence[OperatorNetwork]
) -> tuple[
    dict[tuple[str, str], list[tuple[int, str]]],
    dict[tuple[str, str], list[int]],
]:
    """Split successful Authentication events into operator and foreign logins."""
    from corvus.correlate.correlate import _auth_outcome

    operator: dict[tuple[str, str], list[tuple[int, str]]] = {}
    foreign: dict[tuple[str, str], list[int]] = {}
    for uid in sorted(events):
        event = events[uid]
        if not isinstance(event, Authentication) or _auth_outcome(event) != "success":
            continue
        keys = event.entity_keys
        if keys.host is None or keys.user is None or keys.src_ip is None:
            continue
        pair = (keys.host, keys.user)
        if _inside(keys.src_ip, networks):
            operator.setdefault(pair, []).append((event.time, uid))
        else:
            foreign.setdefault(pair, []).append(event.time)
    return operator, foreign


def mark_operator_findings(
    candidates: Sequence[SessionCandidate],
    findings_by_uid: Mapping[str, DetectionFinding],
    events: Mapping[str, OcsfEvent],
    networks: Sequence[OperatorNetwork],
    gap_ms: int,
) -> dict[str, str]:
    """Return ``{finding uid: operator login event uid}`` for marked findings.

    Pure and order-independent: candidates and logins are walked per
    ``(host, user)`` in ``(time, kind, uid)`` order, logins first at
    equal times. Empty ``networks`` marks nothing.
    """
    if not networks:
        return {}
    operator_logins, foreign_logins = _logins(events, networks)
    if not operator_logins:
        return {}
    per_pair: dict[tuple[str, str], list[SessionCandidate]] = {}
    for candidate in candidates:
        if len(candidate.hosts) != 1 or len(candidate.users) != 1:
            continue
        pair = (next(iter(candidate.hosts)), next(iter(candidate.users)))
        if pair not in operator_logins:
            continue
        if not all(_inside(ip, networks) for ip in candidate.remote_ips):
            continue
        if not _session_techniques_only(candidate.techniques):
            continue
        per_pair.setdefault(pair, []).append(candidate)
    marked: dict[str, str] = {}
    for pair in sorted(per_pair):
        timeline: list[tuple[int, int, str, SessionCandidate | None]] = [
            (when, 0, uid, None) for when, uid in operator_logins[pair]
        ]
        timeline.extend((c.time, 1, c.uid, c) for c in per_pair[pair])
        timeline.sort(key=lambda item: (item[0], item[1], item[2]))
        sessions: list[_Session] = []
        active: _Session | None = None
        for when, kind, uid, member in timeline:
            if kind == 0:
                if active is not None and when - active.last <= gap_ms:
                    active.last = when
                else:
                    active = _Session(start=when, last=when, login_uid=uid)
                    sessions.append(active)
                continue
            if active is None or when - active.last > gap_ms:
                active = None
                continue
            assert member is not None
            active.members.append(member)
            active.last = when
        foreign = foreign_logins.get(pair, [])
        for session in sessions:
            if any(
                session.start - gap_ms <= when <= session.last + gap_ms
                for when in foreign
            ):
                continue  # ambiguous: someone else logged in as this user
            for member in session.members:
                if _has_injection(
                    findings_by_uid.get(member.uid), member.referenced_uids, events
                ):
                    continue
                marked[member.uid] = session.login_uid
    return marked
