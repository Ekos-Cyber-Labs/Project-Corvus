"""Wazuh alert/archive JSON -> OCSF (pinned OCSF 1.9.0).

Each Wazuh alert (``wazuh-alerts-4.x-*``) becomes one Detection Finding
(2004): the rule id, level, description, groups and the rule's MITRE
ids land in typed fields (``finding_info``/``analytic``/``attacks`` and
``severity_id``), and when the decoder maps to an event that event is
emitted alongside with the finding's evidence pointing at it. Archive
documents (``wazuh-archives-4.x-*``) carry no rule match, so they map
to the underlying event only.

Field names follow the live Wazuh 4.14 indexer shapes: the envelope
(``agent``/``manager``/``rule``/``decoder``/``data``/``full_log``/
``location``/``timestamp``/``id``); ``srcuser``/``dstuser``/``command``
for sudo (decoder ``sudo``); ``data.audit.*`` (including
``execve.a0..aN``) for auditd SYSCALL documents (decoder ``auditd``);
``syscheck.path``/``syscheck.event``/``md5_after``/``sha256_after``
for the ``syscheck_new_entry``, ``syscheck_integrity_changed`` and
``syscheck_deleted`` decoders; rule MITRE ids per the Wazuh ruleset
(``<mitre><id>``, a list of technique ids). Decoder ``name`` selects
the mapping; anything else is counted per ``(decoder, rule id)`` and
never dropped (the alert finding is still emitted; only the
underlying event has no typed form). Only SYSCALL auditd documents
map (they already carry ``exe`` and the ``execve`` arguments);
EXECVE, CWD, PATH, PROCTITLE and other auditd record types count as
unmapped, so one execution never yields duplicate events. The raw
alert stays attached as ``raw_data``.

Wazuh rule level 1-15 maps to OCSF ``severity_id`` (our documented
choice; Wazuh documents the levels but no OCSF mapping): 1-3 Low (2),
4-7 Medium (3), 8-11 High (4), 12-15 Critical (5). Level 0 never
reaches the indexer; a level outside 0-15 clamps to the nearest end.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from corvus.normalize.ocsf import (
    Actor,
    Analytic,
    AttackRef,
    Authentication,
    DetectionFinding,
    Device,
    Endpoint,
    Evidence,
    File,
    FileSystemActivity,
    FindingInfo,
    Fingerprint,
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

__all__ = [
    "SUPPORTED_DECODERS",
    "map_alert",
    "map_archive",
    "parse_wazuh_time",
    "severity_for_level",
]

#: Decoders with a typed event mapping (``decoder.name`` values, as the
#: live Wazuh 4.14 indexer returns them).
SUPPORTED_DECODERS = frozenset(
    {
        "sshd",
        "sudo",
        "auditd",
        "syscheck_new_entry",
        "syscheck_integrity_changed",
        "syscheck_deleted",
    }
)

#: auditd ``auid`` value meaning "unset" (no login session); fall back
#: to ``uid`` instead of ever using it as a user name.
_AUDITD_UNSET_AUID = "4294967295"

#: Wazuh product marker on every emitted record.
_WAZUH_PRODUCT = Product(name="wazuh", vendor_name="Wazuh")

#: OCSF severity caption per id (pinned OCSF 1.9.0 ``dictionary.json``).
_SEVERITY_NAMES = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

#: syscheck event word -> File System Activity id (pinned OCSF 1.9.0
#: ``events/system/file_activity.json``: 1 Create, 3 Update, 4 Delete).
_SYSCHECK_ACTIVITIES = {"added": 1, "modified": 3, "deleted": 4}

#: Hash field suffix -> Fingerprint algorithm (names/ids per the pinned
#: OCSF 1.9.0 ``objects/fingerprint.json`` enum, as in windows.py).
_HASH_ALGORITHMS = {"md5": ("MD5", 1), "sha1": ("SHA-1", 2), "sha256": ("SHA-256", 3)}

_SUCCESS_GROUPS = "authentication_success"
_FAILURE_GROUPS = "authentication_failed"


def parse_wazuh_time(value: str | int | float | None) -> int:
    """Parse a Wazuh timestamp to UTC epoch milliseconds.

    Accepts the documented alert ``timestamp`` shape
    (``2024-05-02T12:00:00.048+0000``, ``@timestamp`` ISO with ``Z``
    or ``+00:00``) and integer epoch milliseconds. Naive datetimes
    are read as UTC; anything unparseable raises ``ValueError``.
    """
    if isinstance(value, bool):
        raise ValueError(f"wazuh timestamp {value!r} is not a time")
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"wazuh timestamp {value!r} is not a time")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    match = re.match(r"^(.*)([+-])(\d{2})(\d{2})$", text)
    if match and ":" not in text[-3:]:
        text = f"{match.group(1)}{match.group(2)}{match.group(3)}:{match.group(4)}"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"wazuh timestamp {value!r} is not ISO-8601") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return int(moment.timestamp() * 1000)


def severity_for_level(level: int) -> tuple[int, str]:
    """Map a Wazuh rule level (1-15) to ``(severity_id, caption)``."""
    clamped = min(max(int(level), 0), 15)
    if clamped <= 3:
        severity_id = 2
    elif clamped <= 7:
        severity_id = 3
    elif clamped <= 11:
        severity_id = 4
    else:
        severity_id = 5
    return severity_id, _SEVERITY_NAMES[severity_id]


def _data_fields(source: dict[str, Any]) -> dict[str, Any]:
    """Merge ``data.*`` with the documented top-level event fields.

    Newer indexer documents nest decoded fields under ``data``; older
    alert JSON carries ``srcuser``/``dstuser``/``command`` at the top
    level (see the sudo fixture). The top level wins on conflict.
    Only the documented field names are read; nothing else merges.
    """
    merged: dict[str, Any] = {}
    data = source.get("data")
    if isinstance(data, dict):
        merged.update(data)
    for key in (
        "srcuser",
        "dstuser",
        "srcip",
        "srcport",
        "command",
        "tty",
        "pwd",
        "audit",
        "syscheck",
    ):
        if key in source:
            merged[key] = source[key]
    return merged


def _str(value: Any) -> str | None:
    """Return stripped text, or None for missing/placeholder values."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text or text.lower() in ("", "-", "n/a", "unknown"):
        return None
    return text


def _int(value: Any) -> int | None:
    """Return an int for a digit string or int, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _device(source: dict[str, Any]) -> Device | None:
    """Build the device from the alert ``agent`` block."""
    agent = source.get("agent")
    if not isinstance(agent, dict):
        return None
    hostname = _str(agent.get("name"))
    ip = _str(agent.get("ip"))
    if hostname is None and ip is None:
        return None
    return Device(hostname=hostname, ip=ip, type="Unknown", type_id=0)


def _metadata(uid: str, decoder: str, device: Device | None) -> Metadata:
    """Build the OCSF metadata envelope for one Wazuh document."""
    return Metadata(
        product=_WAZUH_PRODUCT,
        log_name=decoder,
        uid=uid,
        profiles=["host"] if device is not None else None,
    )


def _rule(source: dict[str, Any]) -> dict[str, Any]:
    """Return the alert ``rule`` block (alerts only; archives lack it)."""
    rule = source.get("rule")
    if not isinstance(rule, dict):
        raise ValueError("wazuh alert has no rule block")
    return rule


def _groups(rule: dict[str, Any]) -> list[str]:
    """Return the rule groups as strings (empty when absent)."""
    groups = rule.get("groups")
    if not isinstance(groups, list):
        return []
    return [str(group) for group in groups]


def _attacks(rule: dict[str, Any]) -> list[AttackRef]:
    """Build typed ATT&CK refs from the rule's MITRE block.

    ``rule.mitre`` carries parallel ``id``/``tactic``/``technique``
    arrays. ``TA####`` ids become tactics, ``T####(.###)?`` ids become
    techniques (a sub-technique keeps its parent in ``technique``);
    names come from the same-kind array by position, else stay None.
    Unknown shapes are skipped, never raised.
    """
    mitre = rule.get("mitre")
    if not isinstance(mitre, dict):
        return []
    ids = mitre.get("id")
    if not isinstance(ids, list):
        return []
    tactics = mitre.get("tactic")
    tactic_names = tactics if isinstance(tactics, list) else []
    techniques = mitre.get("technique")
    technique_names = techniques if isinstance(techniques, list) else []
    attacks: list[AttackRef] = []
    tactic_pos = 0
    technique_pos = 0
    for raw in ids:
        if not isinstance(raw, str):
            continue
        uid = raw.strip().upper()
        if re.fullmatch(r"TA\d+", uid):
            name = tactic_names[tactic_pos] if tactic_pos < len(tactic_names) else None
            tactic_pos += 1
            attacks.append(
                AttackRef(
                    tactic=TacticRef(
                        uid=uid, name=str(name) if name is not None else None
                    )
                )
            )
        elif re.fullmatch(r"T\d+(\.\d+)?", uid):
            name = (
                technique_names[technique_pos]
                if technique_pos < len(technique_names)
                else None
            )
            technique_pos += 1
            label = str(name) if name is not None else None
            if "." in uid:
                parent, _, _sub = uid.partition(".")
                attacks.append(
                    AttackRef(
                        technique=TechniqueRef(uid=parent, name=None),
                        sub_technique=TechniqueRef(uid=uid, name=label),
                    )
                )
            else:
                attacks.append(AttackRef(technique=TechniqueRef(uid=uid, name=label)))
    return attacks


def _map_sshd(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> Authentication:
    """Map an sshd record to Authentication (3002, Logon).

    Success comes from the ``authentication_success`` rule group (alerts)
    or the documented OpenSSH ``Accepted`` log wording (archives, which
    carry no rule); ``Failed``/``authentication_failed`` means failure.
    """
    rule = source.get("rule")
    groups = _groups(rule) if isinstance(rule, dict) else []
    full_log = _str(source.get("full_log")) or ""
    if _SUCCESS_GROUPS in groups or "Accepted" in full_log:
        status, status_id = "Success", 1
    elif _FAILURE_GROUPS in groups or "Failed" in full_log:
        status, status_id = "Failure", 2
    else:
        status, status_id = "Unknown", 0
    username = _str(fields.get("srcuser")) or _str(fields.get("dstuser"))
    if username is None:
        # The pinned schema requires the authentication subject; a
        # record without any user has no typed form.
        raise ValueError("sshd record has no user")
    user = User(name=username)
    return Authentication(
        time=time_ms,
        activity_id=1,
        status=status,
        status_id=status_id,
        user=user,
        actor=Actor(user=User(name=username) if username is not None else None),
        device=device,
        src_endpoint=Endpoint(
            ip=_str(fields.get("srcip")), port=_int(fields.get("srcport"))
        ),
        metadata=_metadata(uid, decoder, device),
        raw_data=json.dumps(source),
    )


def _map_sudo(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> ProcessActivity:
    """Map a sudo record to Process Activity (1007, Launch).

    The invoking user (``srcuser``) is the actor, the target user
    (``dstuser``, ``USER=root``) is the user the process runs as, and
    ``command`` is the launched command line. Records without a command
    have no process to type, so they count as unmapped.
    """
    command = _str(fields.get("command"))
    if command is None:
        raise ValueError("sudo record has no command")
    argv0 = command.split()[0]
    name = argv0.rsplit("/", 1)[-1] or None
    invoking = _str(fields.get("srcuser"))
    effective = _str(fields.get("dstuser"))
    unmapped: dict[str, Any] = {}
    for key in ("tty", "pwd"):
        value = _str(fields.get(key))
        if value is not None:
            unmapped[key] = value
    return ProcessActivity(
        time=time_ms,
        activity_id=1,
        actor=Actor(user=User(name=invoking) if invoking is not None else None),
        device=device,
        process=Process(
            name=name,
            cmd_line=command,
            file=(
                File(path=argv0, type="Executable File", type_id=8)
                if argv0.startswith("/")
                else None
            ),
            user=User(name=effective) if effective is not None else None,
        ),
        metadata=_metadata(uid, decoder, device),
        raw_data=json.dumps(source),
        unmapped=unmapped,
    )


def _map_audit(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> ProcessActivity:
    """Map an auditd SYSCALL record to Process Activity (1007).

    The command line rebuilds from ``audit.execve.a0..aN`` in index
    order (falling back to ``audit.command``); ``audit.exe`` is the
    image, ``audit.pid`` the pid, ``audit.auid`` the actor and
    ``audit.euid`` the effective user. An ``auid`` of 4294967295 means
    unset and falls back to ``uid``. Non-SYSCALL record types (EXECVE,
    CWD, PATH, PROCTITLE, ...) and records without an image and
    without a command count as unmapped.
    """
    audit = fields.get("audit")
    if not isinstance(audit, dict):
        raise ValueError("audit record has no audit block")
    audit_type = _str(audit.get("type"))
    if audit_type != "SYSCALL":
        raise ValueError(f"auditd record type {audit_type!r} has no typed mapping")
    raw_execve = audit.get("execve")
    parts: list[str] = []
    if isinstance(raw_execve, dict):
        ordered: list[tuple[int, str]] = []
        for key, value in raw_execve.items():
            if key == "argc":
                continue
            index = _int(key[1:] if key.startswith("a") else key)
            text = _str(value)
            if index is not None and text is not None:
                ordered.append((index, text))
        parts = [text for _, text in sorted(ordered)]
    command = " ".join(parts) if parts else _str(audit.get("command"))
    exe = _str(audit.get("exe"))
    if command is None and exe is None:
        raise ValueError("audit record has no command or exe")
    auid = _str(audit.get("auid"))
    if auid == _AUDITD_UNSET_AUID:
        auid = None
    invoked = auid or _str(audit.get("uid"))
    effective = _str(audit.get("euid")) or _str(audit.get("uid"))
    unmapped: dict[str, Any] = {}
    for key in ("type", "id", "arch", "syscall", "success", "tty", "session", "key"):
        value = audit.get(key)
        if _str(value) is not None:
            unmapped[f"audit.{key}"] = value
    return ProcessActivity(
        time=time_ms,
        activity_id=1,
        actor=Actor(user=User(name=invoked) if invoked is not None else None),
        device=device,
        process=Process(
            pid=_int(audit.get("pid")),
            name=(command or exe or "").split()[0].rsplit("/", 1)[-1] or None,
            cmd_line=command,
            file=(
                File(path=exe, type="Executable File", type_id=8)
                if exe is not None
                else None
            ),
            user=User(name=effective) if effective is not None else None,
        ),
        metadata=_metadata(uid, decoder, device),
        raw_data=json.dumps(source),
        unmapped=unmapped,
    )


def _map_syscheck(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> FileSystemActivity:
    """Map a syscheck record to File System Activity (1001).

    ``syscheck.event`` (added/modified/deleted) selects the activity;
    ``syscheck.path`` is the file and the ``*_after`` digests become
    typed fingerprints. Records without a path count as unmapped.
    """
    syscheck = fields.get("syscheck")
    if not isinstance(syscheck, dict):
        raise ValueError("syscheck record has no syscheck block")
    path = _str(syscheck.get("path"))
    if path is None:
        raise ValueError("syscheck record has no path")
    event = (_str(syscheck.get("event")) or "").lower()
    fingerprints: list[Fingerprint] = []
    unmapped: dict[str, Any] = {}
    for key, value in syscheck.items():
        text = _str(value)
        if text is None:
            continue
        if key.endswith("_after"):
            algo = key[: -len("_after")]
            mapped = _HASH_ALGORITHMS.get(algo)
            if mapped is not None:
                caption, algorithm_id = mapped
                fingerprints.append(
                    Fingerprint(
                        algorithm=caption, algorithm_id=algorithm_id, value=text
                    )
                )
                continue
        if key not in ("path", "event"):
            unmapped[f"syscheck.{key}"] = value
    return FileSystemActivity(
        time=time_ms,
        activity_id=_SYSCHECK_ACTIVITIES.get(event, 0),
        actor=Actor(),
        device=device,
        # The record never names the file kind, so Unknown (never a guess).
        file=File(path=path, type="Unknown", type_id=0, hashes=fingerprints or None),
        metadata=_metadata(uid, decoder, device),
        raw_data=json.dumps(source),
        unmapped=unmapped,
    )


def _map_event(
    source: dict[str, Any], uid: str
) -> tuple[OcsfEvent | None, tuple[str, str | None] | None]:
    """Map one Wazuh document to its underlying event.

    Returns ``(event, None)`` when the decoder maps, else
    ``(None, (decoder, rule_id))`` for the unmapped counter. Records
    missing a required typed attribute (no sshd user, no sudo command,
    no syscheck path) count as unmapped rather than raising.
    """
    decoder_block = source.get("decoder")
    decoder = (
        _str(decoder_block.get("name"))
        if isinstance(decoder_block, dict)
        else _str(decoder_block)
    ) or "unknown"
    rule = source.get("rule")
    rule_id: str | None = None
    if isinstance(rule, dict) and rule.get("id") is not None:
        rule_id = str(rule.get("id"))
    try:
        time_ms = parse_wazuh_time(source.get("timestamp") or source.get("@timestamp"))
    except ValueError, TypeError:
        return None, (decoder, rule_id)
    device = _device(source)
    fields = _data_fields(source)
    try:
        if decoder == "sshd":
            event: OcsfEvent | None = _map_sshd(
                source=source,
                fields=fields,
                decoder=decoder,
                uid=uid,
                time_ms=time_ms,
                device=device,
            )
        elif decoder == "sudo":
            event = _map_sudo(
                source=source,
                fields=fields,
                decoder=decoder,
                uid=uid,
                time_ms=time_ms,
                device=device,
            )
        elif decoder == "auditd":
            event = _map_audit(
                source=source,
                fields=fields,
                decoder=decoder,
                uid=uid,
                time_ms=time_ms,
                device=device,
            )
        elif decoder in (
            "syscheck_new_entry",
            "syscheck_integrity_changed",
            "syscheck_deleted",
        ):
            event = _map_syscheck(
                source=source,
                fields=fields,
                decoder=decoder,
                uid=uid,
                time_ms=time_ms,
                device=device,
            )
        else:
            return None, (decoder, rule_id)
    except ValueError, ValidationError:
        return None, (decoder, rule_id)
    return event, None


def _build_finding(
    source: dict[str, Any],
    rule: dict[str, Any],
    uid: str,
    time_ms: int,
    device: Device | None,
    decoder: str,
    event: OcsfEvent | None,
) -> DetectionFinding:
    """Build the Detection Finding (2004) for one Wazuh alert."""
    rule_id = rule.get("id")
    description = _str(rule.get("description")) or f"Wazuh rule {rule_id}"
    level = _int(rule.get("level"))
    severity_id, severity = severity_for_level(level if level is not None else 0)
    groups = _groups(rule)
    firedtimes = _int(rule.get("firedtimes"))
    analytic = Analytic(
        name=description,
        uid=str(rule_id) if rule_id is not None else None,
        desc=description,
        category=",".join(groups) if groups else None,
        type="Rule",
        type_id=1,
    )
    attacks = _attacks(rule)
    if event is not None:
        evidence = Evidence(
            uid=event.metadata.uid,
            actor=event.actor,
            process=getattr(event, "process", None),
            src_endpoint=event.src_endpoint,
            dst_endpoint=event.dst_endpoint,
            device=event.device,
            file=getattr(event, "file", None),
        )
        related = [
            RelatedEvent(
                uid=event.metadata.uid,
                type_uid=event.class_uid * 100 + event.activity_id,
            )
        ]
        evidences = [evidence]
    else:
        related = []
        evidences = None
    unmapped: dict[str, Any] = {}
    if firedtimes is not None:
        unmapped["firedtimes"] = firedtimes
    return DetectionFinding(
        time=time_ms,
        severity_id=severity_id,
        severity=severity,
        status="New",
        status_id=1,
        activity_id=1,
        start_time=time_ms,
        end_time=time_ms,
        metadata=_metadata(uid, decoder, device),
        device=device,
        finding_info=FindingInfo(
            uid=uid,
            title=description,
            desc=description,
            analytic=analytic,
            attacks=attacks or None,
            related_events=related or None,
        ),
        evidences=evidences,
        raw_data=json.dumps(source),
        unmapped=unmapped,
    )


def map_alert(
    hit: dict[str, Any],
) -> tuple[DetectionFinding, OcsfEvent | None, tuple[str, str | None] | None]:
    """Map one alerts-index hit to ``(finding, event, unmapped_key)``.

    ``hit`` is the OpenSearch hit (``_id``/``_source``); the finding uid
    is the alert ``id`` field. The finding is always built; ``event``
    is None (with ``unmapped_key`` set to ``(decoder, rule id)``) when
    the decoder has no typed mapping. Hits without a rule block or
    without a parseable time raise ``ValueError``.
    """
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise ValueError("wazuh hit has no _source")
    rule = _rule(source)
    alert_id = _str(source.get("id"))
    if alert_id is None:
        raise ValueError("wazuh alert has no id")
    time_ms = parse_wazuh_time(source.get("timestamp") or source.get("@timestamp"))
    decoder_block = source.get("decoder")
    decoder = (
        _str(decoder_block.get("name"))
        if isinstance(decoder_block, dict)
        else _str(decoder_block)
    ) or "unknown"
    device = _device(source)
    event, unmapped_key = _map_event(source, f"{alert_id}#event")
    finding = _build_finding(source, rule, alert_id, time_ms, device, decoder, event)
    return finding, event, unmapped_key


def map_archive(
    hit: dict[str, Any],
) -> tuple[OcsfEvent | None, tuple[str, str | None] | None]:
    """Map one archives-index hit to ``(event, unmapped_key)``.

    Archives carry the raw event with no rule match, so no finding is
    built. The ``id`` field repeats across archive documents, so the
    event uid is the document ``_id`` (unique per document); the Wazuh
    ``id`` is kept verbatim in ``unmapped`` as ``wazuh_id``. Hits
    without a document ``_id`` count as ``("unknown", None)``.
    """
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise ValueError("wazuh hit has no _source")
    doc_uid = hit.get("_id")
    if not isinstance(doc_uid, str) or not doc_uid:
        return None, ("unknown", None)
    decoder_block = source.get("decoder")
    decoder = (
        _str(decoder_block.get("name"))
        if isinstance(decoder_block, dict)
        else _str(decoder_block)
    ) or "unknown"
    if decoder not in SUPPORTED_DECODERS:
        rule = source.get("rule")
        rule_id = (
            str(rule.get("id"))
            if isinstance(rule, dict) and rule.get("id") is not None
            else None
        )
        return None, (decoder, rule_id)
    event, unmapped_key = _map_event(source, doc_uid)
    if event is None:
        return None, unmapped_key or (decoder, None)
    wazuh_id = _str(source.get("id"))
    if wazuh_id is not None:
        event.unmapped["wazuh_id"] = wazuh_id
    return event, None
