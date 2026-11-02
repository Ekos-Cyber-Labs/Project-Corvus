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
underlying event has no typed form). Auditd documents route by
record: execve SYSCALLs map with the EXECVE/PROCTITLE records joined
by serial (hex decoded), ``connect`` maps with the decoded ``SADDR``
peer, file-operation syscalls map with their PATH records, and
PAM/accounting records (``USER_AUTH``, ``USER_START``, ``LOGIN``,
``USER_END``, ``USER_CMD``) map where the schema has a class;
standalone EXECVE/CWD/PATH/PROCTITLE companions, ``socket()``,
process bookkeeping, BPF, service and credential records count as
unmapped, so one execution yields one event. PAM session lines and
``su`` invocations map to Authentication; cron sessions are tagged
for later filtering. Event time comes from the log line (UTC), not
the manager receive time. The raw alert stays attached as
``raw_data``.

Wazuh rule level 1-15 maps to OCSF ``severity_id`` (our documented
choice; Wazuh documents the levels but no OCSF mapping): 1-3 Low (2),
4-7 Medium (3), 8-11 High (4), 12-15 Critical (5). Level 0 never
reaches the indexer; a level outside 0-15 clamps to the nearest end.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
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
    NetworkActivity,
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
    "LINUX_USERNAME_CAP",
    "SUPPORTED_DECODERS",
    "decode_audit_hex",
    "linux_dedup_key",
    "map_alert",
    "map_archive",
    "map_linux_doc",
    "parse_linux_time",
    "parse_wazuh_time",
    "parse_wazuh_time_unbounded",
    "severity_for_level",
]

#: Decoders with a typed event mapping (``decoder.name`` values, as the
#: live Wazuh 4.14 indexer returns them).
SUPPORTED_DECODERS = frozenset(
    {
        "sshd",
        "sudo",
        "su",
        "pam",
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
    are read as UTC; anything unparseable, non-finite, before
    2000-01-01 UTC or after 2100-01-01 UTC raises ``ValueError``
    (never ``OverflowError``).
    """
    from corvus.normalize.ocsf import MAX_TIME_MS, MIN_TIME_MS

    if isinstance(value, bool):
        raise ValueError(f"wazuh timestamp {value!r} is not a time")
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"wazuh timestamp {value!r} is not a time")
        try:
            ms = int(number)
        except (OverflowError, ValueError) as exc:
            raise ValueError(f"wazuh timestamp {value!r} is not a time") from exc
        if ms < MIN_TIME_MS:
            raise ValueError(f"wazuh timestamp {value!r} is before 2000-01-01 UTC")
        if ms > MAX_TIME_MS:
            raise ValueError(f"wazuh timestamp {value!r} is after 2100-01-01 UTC")
        return ms
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
    try:
        ms = int(moment.timestamp() * 1000)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"wazuh timestamp {value!r} is not a time") from exc
    if ms < MIN_TIME_MS:
        raise ValueError(f"wazuh timestamp {value!r} is before 2000-01-01 UTC")
    if ms > MAX_TIME_MS:
        raise ValueError(f"wazuh timestamp {value!r} is after 2100-01-01 UTC")
    return ms


def parse_wazuh_time_unbounded(value: str | int | float | None) -> int:
    """Parse a Wazuh timestamp without the 2000/2100 window checks.

    Same shapes and ``ValueError``-only errors as
    :func:`parse_wazuh_time`, but no floor or ceiling: far-future
    alert timestamps (for example year 2999) still parse so the live
    poll can count them as ``future_dated`` and withhold checkpoint
    progress instead of dropping them as unmapped.
    """
    if isinstance(value, bool):
        raise ValueError(f"wazuh timestamp {value!r} is not a time")
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"wazuh timestamp {value!r} is not a time")
        try:
            return int(number)
        except (OverflowError, ValueError) as exc:
            raise ValueError(f"wazuh timestamp {value!r} is not a time") from exc
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
    try:
        return int(moment.timestamp() * 1000)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"wazuh timestamp {value!r} is not a time") from exc


def _far_future_ms(value: Any) -> int:
    """Return ``value`` as epoch ms when it is a far-future ISO timestamp.

    Only ISO strings past 2100-01-01 UTC qualify (the live poll's
    ``future_dated`` clock abuse, for example year 2999); hostile
    numbers stay rejected so they keep counting as unmapped.
    Raises ``ValueError`` for anything else.
    """
    from corvus.normalize.ocsf import MAX_TIME_MS

    if not isinstance(value, str):
        raise ValueError(f"wazuh timestamp {value!r} is not far-future ISO-8601")
    ms = parse_wazuh_time_unbounded(value)
    if ms <= MAX_TIME_MS:
        raise ValueError(f"wazuh timestamp {value!r} is not past 2100-01-01 UTC")
    return ms


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


def _sanitize_str(value: str) -> tuple[str, bool]:
    """Replace NUL and lone surrogates with U+FFFD.

    Postgres UTF-8 text (and ``jsonb``) rejects both, so either would
    raise on insert down the pipeline (findings, incidents, analyses).
    Returns the cleaned string plus whether anything was replaced.
    """
    bad = False
    out: list[str] = []
    for char in value:
        code = ord(char)
        if code == 0 or 0xD800 <= code <= 0xDFFF:
            out.append("\ufffd")
            bad = True
        else:
            out.append(char)
    if not bad:
        return value, False
    return "".join(out), True


def _sanitize_value(value: Any) -> tuple[Any, bool]:
    """Recursively sanitize every string leaf of ``value``."""
    if isinstance(value, str):
        return _sanitize_str(value)
    if isinstance(value, dict):
        changed = False
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            clean_key, key_bad = (
                _sanitize_str(key) if isinstance(key, str) else (key, False)
            )
            clean_item, item_bad = _sanitize_value(item)
            changed = changed or key_bad or item_bad
            cleaned[clean_key] = clean_item
        return cleaned, changed
    if isinstance(value, list):
        changed = False
        cleaned_list: list[Any] = []
        for item in value:
            clean_item, item_bad = _sanitize_value(item)
            changed = changed or item_bad
            cleaned_list.append(clean_item)
        return cleaned_list, changed
    if isinstance(value, tuple):
        changed = False
        cleaned_items: list[Any] = []
        for item in value:
            clean_item, item_bad = _sanitize_value(item)
            changed = changed or item_bad
            cleaned_items.append(clean_item)
        return tuple(cleaned_items), changed
    return value, False


def _int(value: Any) -> int | None:
    """Return an int for a digit string or int, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _device(source: dict[str, Any], unmapped: dict[str, Any]) -> Device | None:
    """Build the device from the alert ``agent`` block.

    The agent name and ip land in typed slots (and entity keys), so
    both are capped at :data:`WAZUH_RAW_DATA_CAP` with the original
    length in ``unmapped``.
    """
    agent = source.get("agent")
    if not isinstance(agent, dict):
        return None
    hostname = _cap_typed(
        _str(agent.get("name")), unmapped, "wazuh.agent_name_truncated"
    )
    ip = _cap_typed(_str(agent.get("ip")), unmapped, "wazuh.agent_ip_truncated")
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


#: Verbatim cap on an attacker-controlled Linux user name kept in
#: ``User.name``. Longer names truncate here; the original length
#: lands in ``unmapped["linux.username_truncated"]`` (the full line in
#: ``raw_data`` is itself leaf-capped by :data:`WAZUH_RAW_DATA_CAP`,
#: so over-long values are kept nowhere — only their lengths).
LINUX_USERNAME_CAP = 256

#: Bound on string leaves kept in ``raw_data``: the same documented
#: length as :data:`corvus.normalize.windows.WINDOWS_TEXT_CAP`
#: (asserted equal in ``tests/test_raw_data_cap.py``; kept as a local
#: constant so the two normalizers stay independent). Wazuh
#: alert/archive documents were previously stored whole
#: (``json.dumps(source)`` unbounded: a hostile ``full_log`` could
#: grow one event without bound). Longer leaves truncate here; the
#: original length lands in
#: ``unmapped["wazuh.raw_data_truncated"]`` as ``{json_path: length}``.
WAZUH_RAW_DATA_CAP = 65536


def _cap_raw_leaves(value: Any, truncated: dict[str, int], path: str = "$") -> Any:
    """Truncate over-long string leaves for ``raw_data``.

    Every string leaf longer than :data:`WAZUH_RAW_DATA_CAP`
    truncates there; ``truncated`` records the JSON path
    (``$.a[0].b``) to the original length, so nothing is silently
    lost. Dict keys are never truncated (schema, not attacker text);
    tuple and list shapes are preserved.
    """
    if isinstance(value, str):
        if len(value) > WAZUH_RAW_DATA_CAP:
            truncated[path] = len(value)
            return value[:WAZUH_RAW_DATA_CAP]
        return value
    if isinstance(value, dict):
        return {
            key: _cap_raw_leaves(item, truncated, f"{path}.{key}")
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _cap_raw_leaves(item, truncated, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, tuple):
        return tuple(
            _cap_raw_leaves(item, truncated, f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    return value


def _cap_typed(value: str | None, unmapped: dict[str, Any], key: str) -> str | None:
    """Truncate a typed-slot string to :data:`WAZUH_RAW_DATA_CAP`.

    The same documented bound as :data:`WAZUH_RAW_DATA_CAP` (asserted
    equal to the Windows ``WINDOWS_TEXT_CAP``) applies to every string
    the mappers copy into a typed slot, a finding title or an entity
    key; longer values truncate here and the original length lands in
    ``unmapped[key]``. The attacker-controlled Linux user name keeps
    its own shorter :data:`LINUX_USERNAME_CAP` and never routes here.
    """
    if value is None:
        return None
    if len(value) > WAZUH_RAW_DATA_CAP:
        unmapped[key] = len(value)
        return value[:WAZUH_RAW_DATA_CAP]
    return value


def _capped_raw(source: dict[str, Any], unmapped: dict[str, Any]) -> str:
    """Serialize ``source`` for ``raw_data`` with long leaves capped.

    Records ``{json_path: original_length}`` under
    ``unmapped["wazuh.raw_data_truncated"]`` when anything
    truncated. Key order and separators match the previous bare
    ``json.dumps(source)`` exactly, so uncapped documents serialize
    byte for byte as before.
    """
    truncated: dict[str, int] = {}
    capped = _cap_raw_leaves(source, truncated)
    if truncated:
        unmapped["wazuh.raw_data_truncated"] = truncated
    return json.dumps(capped, default=str)


#: Bound on EXECVE arguments parsed from one audit blob (a corrupt
#: ``argc`` must not balloon memory; the cap lands in ``unmapped``).
_LINUX_MAX_EXECVE_ARGS = 4096


def _linux_user(name: Any) -> tuple[str | None, dict[str, Any]]:
    """Return ``(name, unmapped)`` keeping an ssh user verbatim up to cap.

    The name is attacker-controlled, so it is never dropped or
    rewritten (the injection detector must see it); over-long names
    truncate at :data:`LINUX_USERNAME_CAP` with the original length
    recorded. Placeholders and missing values stay missing.
    """
    username = _str(name)
    if username is None:
        return None, {}
    if len(username) > LINUX_USERNAME_CAP:
        return (
            username[:LINUX_USERNAME_CAP],
            {"linux.username_truncated": len(username)},
        )
    return username, {}


#: sshd message parsing (log-injection hardened). Every pattern anchors
#: to the message start (the text after ``sshd[<pid>]: ``), so text
#: inside the attacker-controlled username can never match another
#: message shape. The peer is parsed right to left for every message
#: kind -- the LAST ``<ip> port <port>`` (with or without a preceding
#: ``from``) before the optional ``ssh2`` (plus ``: <key info>``) or
#: ``[preauth]`` suffix -- and the username is everything between the
#: fixed prefix and that peer, spaces included. The address must
#: validate with the :mod:`ipaddress` module; otherwise the source
#: stays unset with ``unmapped["linux.sshd_peer_unparsed"]``.
_SSHD_TAG = re.compile(r"sshd\[\d+\]: ")

#: Message kind at the message start. Only this decides the status;
#: text inside the username never does. ``Received disconnect`` names
#: no user, so it stays unmapped.
_SSHD_KIND = re.compile(
    r"^(?:"
    r"Accepted (?P<accepted_method>password|publickey) for "
    r"|Failed (?P<failed_method>password|publickey) for "
    r"(?P<failed_invalid>invalid user )?"
    r"|Invalid user "
    r"|Disconnected from "
    r"|Connection closed by "
    r"|Received disconnect from "
    r")"
)

#: ``user `` / ``authenticating user `` / ``invalid user `` markers
#: that prefix the username in ``Disconnected`` / ``Connection
#: closed`` lines (OpenSSH wording, not part of the username).
_SSHD_PEER_MARKER = re.compile(r"^(?:user |authenticating user |invalid user )")

#: Peer shape for every sshd message kind, matched right to left
#: (the last valid one wins): ``<ip> port <port>`` with an optional
#: preceding ``from``. ``Accepted``/``Failed``/``Invalid user`` carry
#: the explicit ``from``; ``Disconnected``/``Connection closed`` carry
#: a bare ``<ip> port <port>`` (also on the real attack line:
#: ``... port 22 10.70.1.30 port 39098``). The ``from`` needs a word
#: boundary (``(?<!\S)``): without it the ``from`` inside a username
#: ending in ``from`` (``gfrom 1.2.3.4 port 5``) would be eaten and
#: the username truncated to ``g``.
_SSHD_PEER = re.compile(r"(?:(?<!\S)from )?(?P<ip>\S+) port (?P<port>\d+)")

#: ``Invalid user`` lines without a port (``Invalid user mallory from
#: 203.0.113.9``): the address still needs its ``from`` and must
#: validate as an IP address.
_SSHD_FROM_IP = re.compile(r" from (?P<ip>\S+)(?: port (?P<port>\d+))?")

#: Allowed tails after the peer, shared by every message kind:
#: ``ssh2`` with optional key info (``Accepted``/``Failed``),
#: ``[preauth]`` (``Disconnected``/``Connection closed``), or nothing.
_SSHD_PEER_TAIL = re.compile(r"(?:\s+ssh2(?::.*)?|\s+\[preauth\])?\s*$")


def _sshd_message(full_log: str) -> str:
    """Return the sshd message (text after ``sshd[<pid>]: ``)."""
    match = _SSHD_TAG.search(full_log)
    if match is None:
        return full_log
    return full_log[match.end() :]


def _sshd_last_peer(
    text: str, pattern: re.Pattern[str], tail: re.Pattern[str]
) -> re.Match[str] | None:
    """Return the last ``pattern`` match with a valid ``tail``.

    The captured ``ip`` must parse with the :mod:`ipaddress` module
    (IPv4 or IPv6); a non-address such as ``[preauth]`` never wins,
    no matter where it sits in the line.
    """
    for match in reversed(list(pattern.finditer(text))):
        if tail.match(text[match.end() :]) is None:
            continue
        try:
            ipaddress.ip_address(match.group("ip"))
        except ValueError:
            continue
        return match
    return None


def _map_sshd(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> Authentication:
    """Map an sshd record to Authentication (3002).

    ``Accepted`` (password/publickey) is activity 1 Logon Success;
    ``Failed`` and ``Invalid user`` are activity 1 Logon Failure;
    ``Disconnected from`` and ``Connection closed by`` are activity 2
    Logoff Success (the session existed and terminated). ``Received
    disconnect`` names no user, so it stays unmapped. Only the message
    kind at the message start (after ``sshd[<pid>]: ``) decides the
    status; the peer is the last ``<ip> port <port>`` (with or without
    a preceding ``from``) before the optional ``ssh2`` / ``[preauth]``
    suffix, and the username is everything between the fixed prefix
    and that peer (it may contain spaces, flagged in
    ``unmapped["linux.username_whitespace"]``). A peer that does not
    validate as an IP address is never used: the source stays unset
    with ``unmapped["linux.sshd_peer_unparsed"]`` and the decoded
    ``data`` fields are not consulted for it. The log line wins over
    the Wazuh-decoded ``data`` fields; differing decoded values are
    kept in ``unmapped["linux.decoder_conflict"]``. The auth method
    (password vs publickey) has no typed slot in the pinned 1.9.0
    ``authentication`` event, so it lands in
    ``unmapped["linux.auth_method"]``.
    """
    rule = source.get("rule")
    groups = _groups(rule) if isinstance(rule, dict) else []
    full_log = _str(source.get("full_log")) or ""
    message = _sshd_message(full_log)
    kind_match = _SSHD_KIND.match(message)
    kind: str | None = None
    method: str | None = None
    rest = ""
    if kind_match is not None:
        rest = message[kind_match.end() :]
        if kind_match.group("accepted_method") is not None:
            kind, method = "accepted", kind_match.group("accepted_method")
        elif kind_match.group("failed_method") is not None:
            kind, method = "failed", kind_match.group("failed_method")
        elif message.startswith("Invalid user "):
            kind = "invalid"
        elif message.startswith("Disconnected from "):
            kind = "disconnected"
        elif message.startswith("Connection closed by "):
            kind = "closed"
        else:
            kind = "received"
    username: str | None = None
    ip: str | None = None
    port: int | None = None
    unmapped: dict[str, Any] = {}
    activity_id = 1
    status, status_id = "Unknown", 0
    if kind == "accepted":
        status, status_id = "Success", 1
    elif kind in ("failed", "invalid"):
        status, status_id = "Failure", 2
    elif kind in ("disconnected", "closed"):
        activity_id = 2
        status, status_id = "Success", 1
    elif _SUCCESS_GROUPS in groups:
        status, status_id = "Success", 1
    elif _FAILURE_GROUPS in groups:
        status, status_id = "Failure", 2
    peer: re.Match[str] | None = None
    if kind in ("accepted", "failed"):
        peer = _sshd_last_peer(rest, _SSHD_PEER, _SSHD_PEER_TAIL)
        if peer is not None:
            # The peer match eats ``from `` but not the space before
            # it, so the username slice keeps a trailing space.
            username = rest[: peer.start()].rstrip() or None
        if method is not None:
            unmapped["linux.auth_method"] = method
        if kind == "failed" and kind_match is not None:
            if kind_match.group("failed_invalid") is not None:
                unmapped["linux.invalid_user"] = True
    elif kind == "invalid":
        peer = _sshd_last_peer(rest, _SSHD_PEER, _SSHD_PEER_TAIL)
        if peer is None:
            peer = _sshd_last_peer(rest, _SSHD_FROM_IP, _SSHD_PEER_TAIL)
        if peer is not None:
            username = rest[: peer.start()].rstrip() or None
        unmapped["linux.invalid_user"] = True
    elif kind in ("disconnected", "closed"):
        body = _SSHD_PEER_MARKER.sub("", rest, count=1)
        peer = _sshd_last_peer(body, _SSHD_PEER, _SSHD_PEER_TAIL)
        if peer is not None:
            username = body[: peer.start()].rstrip() or None
    if peer is not None:
        ip = peer.group("ip")
        port = _int(peer.group("port"))
    elif kind in ("accepted", "failed", "invalid", "disconnected", "closed"):
        # No ``<ip> port <port>`` in the line validates as an address:
        # leave the source unset instead of guessing from the text.
        unmapped["linux.sshd_peer_unparsed"] = True
    if username is not None and any(char.isspace() for char in username):
        unmapped["linux.username_whitespace"] = True
    conflict: dict[str, str] = {}
    if username is not None:
        decoded_user = _str(fields.get("srcuser")) or _str(fields.get("dstuser"))
        if decoded_user is not None and decoded_user != username:
            conflict["user"] = decoded_user
    if ip is not None:
        decoded_ip = _str(fields.get("srcip"))
        if decoded_ip is not None and decoded_ip != ip:
            conflict["ip"] = decoded_ip
    if port is not None:
        decoded_port = _str(fields.get("srcport"))
        if decoded_port is not None and _int(decoded_port) != port:
            conflict["port"] = decoded_port
    if conflict:
        unmapped["linux.decoder_conflict"] = conflict
    if username is None:
        username = _str(fields.get("srcuser")) or _str(fields.get("dstuser"))
    if "linux.sshd_peer_unparsed" not in unmapped:
        if ip is None:
            ip = _str(fields.get("srcip"))
        if port is None:
            port = _int(fields.get("srcport"))
    username, capped = _linux_user(username)
    unmapped.update(capped)
    if username is None:
        # The pinned schema requires the authentication subject; a
        # record without any user has no typed form.
        raise ValueError("sshd record has no user")
    user = User(name=username)
    ip = _cap_typed(ip, unmapped, "wazuh.src_ip_truncated")
    endpoint: Endpoint | None = None
    if ip is not None or port is not None:
        endpoint = Endpoint(ip=ip, port=port)
    return Authentication(
        time=time_ms,
        activity_id=activity_id,
        status=status,
        status_id=status_id,
        user=user,
        actor=Actor(user=User(name=username)),
        device=device,
        src_endpoint=endpoint,
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
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
    unmapped: dict[str, Any] = {}
    command = _cap_typed(
        _str(fields.get("command")), unmapped, "wazuh.command_truncated"
    )
    if command is None:
        raise ValueError("sudo record has no command")
    argv0 = command.split()[0]
    name = argv0.rsplit("/", 1)[-1] or None
    invoking = _cap_typed(
        _str(fields.get("srcuser")), unmapped, "wazuh.srcuser_truncated"
    )
    effective = _cap_typed(
        _str(fields.get("dstuser")), unmapped, "wazuh.dstuser_truncated"
    )
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
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


#: Head of one audit record inside ``full_log``: the record type plus
#: the kernel ``(time:serial)`` stamp every record of an event shares.
#: Records are separated by the ASCII group separator (``\x1d``); the
#: decoder-appended ``ARCH=``/``SADDR=``/``OUID=`` lines carry no head.
_AUDIT_HEAD = re.compile(r"type=([A-Z0-9_]+) msg=audit\((\d+(?:\.\d+)?):(\d+)\):")

#: One ``key=value`` field inside an audit record (``key="quoted"`` or
#: a bare token). Quoted values are literal; bare tokens may be
#: hex-encoded (see :func:`decode_audit_hex`).
_AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')

#: Decoded peer address Wazuh appends to ``connect`` blobs
#: (``SADDR={ saddr_fam=inet laddr=203.0.113.7 lport=123 }``).
#: ``data.audit`` drops the ``SOCKADDR`` record, so the mapper reads
#: the address here; blobs without it stay unmapped.
_AUDIT_SADDR = re.compile(
    r"SADDR=\{\s*saddr_fam=(\S+)\s+laddr=(\S+)\s+lport=(\d+)\s*\}"
)

#: Syscall name Wazuh appends as ``SYSCALL=<name>`` (authoritative;
#: the ``data.audit.syscall`` number is kept verbatim in ``unmapped``).
_AUDIT_SYSCALL_NAME = re.compile(r"\bSYSCALL=([A-Za-z][A-Za-z0-9_]*)")

#: ``acct="..."`` / ``res=...`` / ``exe="..."`` inside PAM session
#: records (``msg='op=PAM:...'``), plus the decoded ``AUID=``/``UID=``
#: the decoder appends.
_AUDIT_ACCT = re.compile(r'\bacct="([^"]*)"')
_AUDIT_RES = re.compile(r"\bres=([A-Za-z_]+)")
_AUDIT_EXE_MSG = re.compile(r'\bexe="([^"]*)"')
_AUDIT_AUID_OF = re.compile(r'\bAUID="([^"]*)"')
_AUDIT_UID_OF = re.compile(r'(?<![A-Z])\bUID="([^"]*)"')

#: ``cmd=<hex>`` (always hex-encoded) and ``cwd="..."`` inside
#: ``USER_CMD`` (sudo) records.
_AUDIT_CMD = re.compile(r"\bcmd=([0-9A-Fa-f]+)")
_AUDIT_CWD_MSG = re.compile(r'\bcwd="([^"]*)"')

#: ``type=PROCTITLE ... proctitle=<hex>`` (NUL-separated, always hex).
_AUDIT_PROCTITLE = re.compile(r"proctitle=([0-9A-Fa-f]*)")

#: ``type=PATH ... item=<n> name="<path>"`` in encounter order.
_AUDIT_PATH = re.compile(r'item=(\d+)\s+name="([^"]*)"')

#: ``type=CWD ... cwd="<dir>"``. The head group is bounded (a real
#: kernel stamp is ~22 chars): an unbounded ``[^)]*`` here scans to
#: the end of the blob from every ``msg=audit(`` occurrence, which is
#: quadratic on hostile input.
_AUDIT_CWD = re.compile(r'type=CWD msg=audit\([^)]{0,64}\):\s*cwd="([^"]*)"')

#: PAM session lines (``pam_unix(<service>:session)``).
_PAM_SESSION = re.compile(
    r"session (opened|closed) for user (?P<user>\S+?)(?:\(uid=\d+\))?"
    r"(?: by (?P<by>\S+?)(?:\(uid=\d+\))?)?\s*$"
)

#: ``su`` invocation lines (``su[pid]: (to <target>) <invoker> on <tty>``).
_SU_LINE = re.compile(r"\(to (?P<target>\S+)\) (?P<invoker>\S+) on (?P<tty>\S+)")

#: Leading timestamps of syslog lines: ISO-8601 (auth.log) or
#: ``Oct 28 00:16:34`` (journald, no year: the manager receive time
#: supplies it, rolling back a year when the line would land in the
#: future). Times are UTC, never the manager receive time.
_SYSLOG_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+"
)
_SYSLOG_SHORT = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+"
)
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

#: Audit record types that are companions of a SYSCALL blob (EXECVE,
#: CWD, PATH, PROCTITLE): on their own they never emit an event (one
#: execution yields one event), so without a SYSCALL they count as
#: unmapped instead of duplicating it.
_AUDIT_COMPANIONS = frozenset({"EXECVE", "CWD", "PATH", "PROCTITLE"})

#: Session/account record types mapped per document (independent of
#: any SYSCALL sharing their serial).
_AUDIT_SESSION_TYPES = frozenset(
    {"USER_AUTH", "USER_START", "USER_END", "LOGIN", "USER_CMD"}
)

#: File-operation syscall names (from the ``SYSCALL=<name>`` decode
#: line) to File System Activity ids (pinned OCSF 1.9.0
#: ``events/system/file_activity.json``: 1 Create, 2 Read, 3 Update,
#: 4 Delete, 5 Rename, 6 Set Attributes, 7 Set Security,
#: 8 Get Attributes, 9 Get Security, 14 Open). The class has no Close
#: or chdir, so those stay unmapped and counted.
_LINUX_FILE_ACTIVITIES = {
    "open": 14,
    "openat": 14,
    "openat2": 14,
    "creat": 1,
    "mkdir": 1,
    "mkdirat": 1,
    "mknod": 1,
    "mknodat": 1,
    "symlink": 1,
    "symlinkat": 1,
    "link": 1,
    "linkat": 1,
    "read": 2,
    "write": 3,
    "truncate": 3,
    "ftruncate": 3,
    "unlink": 4,
    "unlinkat": 4,
    "rmdir": 4,
    "rename": 5,
    "renameat": 5,
    "renameat2": 5,
    "chmod": 6,
    "fchmod": 6,
    "fchmodat": 6,
    "setxattr": 6,
    "lsetxattr": 6,
    "fsetxattr": 6,
    "chown": 7,
    "fchown": 7,
    "lchown": 7,
    "fchownat": 7,
    "stat": 8,
    "lstat": 8,
    "fstat": 8,
    "access": 8,
    "faccessat": 8,
    "faccessat2": 8,
    "statx": 8,
    "getxattr": 9,
    "lgetxattr": 9,
    "fgetxattr": 9,
    "mount": 12,
    "umount2": 13,
    "umount": 13,
}


def decode_audit_hex(value: str) -> tuple[str, int]:
    """Decode one auditd value, returning ``(text, replacements)``.

    auditd hex-encodes a value holding a space or a special character;
    ``PROCTITLE`` and ``USER_CMD.cmd`` are always hex. A bare token
    decodes only when it is unambiguously encoded (even length of at
    least 8 hex digits holding both a digit and an ``a-f`` letter):
    short numbers (``"27"``), plain words (``"dead"``) and plain
    numbers stay verbatim, so decoding never corrupts a value auditd
    left alone. Decoding is UTF-8 with invalid bytes replaced, and
    each replacement is counted.
    """
    if (
        len(value) >= 8
        and len(value) % 2 == 0
        and re.fullmatch(r"[0-9A-Fa-f]+", value) is not None
        and any(char.isdigit() for char in value)
        and any(char in "abcdefABCDEF" for char in value)
    ):
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return value, 0
        text = raw.decode("utf-8", errors="replace")
        return text, text.count("�")
    return value, 0


def _parse_audit_blob(full_log: str) -> dict[str, Any]:
    """Split one audit ``full_log`` blob into its joined records.

    Returns the SYSCALL record fields, the EXECVE argv (index-ordered,
    hex decoded with replacements counted), the PROCTITLE command
    line, PATH names in item order, the CWD, the decoded ``SADDR``
    peer, the syscall name, and the set of audit serials (more than
    one flags ``mismatch``). Quoted EXECVE values stay literal;
    bare hex tokens decode via :func:`decode_audit_hex`.
    """
    blob: dict[str, Any] = {
        "serial": None,
        "time_ms": None,
        "syscall": None,
        "execve": None,
        "proctitle": None,
        "paths": [],
        "cwd": None,
        "saddr": None,
        "serials": set(),
        "mismatch": False,
    }
    heads = list(_AUDIT_HEAD.finditer(full_log))
    for match in heads:
        serial = match.group(3)
        blob["serials"].add(serial)
        if blob["serial"] is None:
            blob["serial"] = serial
            try:
                blob["time_ms"] = int(float(match.group(2)) * 1000)
            except ValueError:
                blob["time_ms"] = None
    if len(blob["serials"]) > 1:
        blob["mismatch"] = True
    syscall_match = _AUDIT_SYSCALL_NAME.search(full_log)
    syscall_name = syscall_match.group(1) if syscall_match else None
    fields: dict[str, str] = {}
    for field in _AUDIT_FIELD.finditer(full_log):
        name, raw = field.group(1), field.group(2)
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            fields[name] = raw[1:-1]
    head_types = [match.group(1) for match in heads]
    if "SYSCALL" in head_types:
        blob["syscall"] = {"name": syscall_name, "fields": fields}
    # The head group is bounded like :data:`_AUDIT_CWD` (same
    # quadratic-input reason); a real kernel stamp is ~22 chars.
    execve_match = re.search(
        r"type=EXECVE msg=audit\([^)]{0,64}\):\s*argc=(\d+)((?:\s+a\d+=\S+)*)",
        full_log,
    )
    if execve_match is not None:
        try:
            argc = int(execve_match.group(1))
        except ValueError:
            argc = 0
        argv: list[tuple[int, str, int]] = []
        replacements = 0
        truncated = False
        for arg in re.finditer(
            r'a(\d+)=("[^"]*"|[0-9A-Fa-f]+|\S+)', execve_match.group(2)
        ):
            index = int(arg.group(1))
            raw_value = arg.group(2)
            if raw_value.startswith('"'):
                argv.append((index, raw_value[1:-1], 0))
            else:
                text, count = decode_audit_hex(raw_value)
                argv.append((index, text, count))
        argv.sort(key=lambda item: item[0])
        ordered = argv[:_LINUX_MAX_EXECVE_ARGS]
        if len(argv) > _LINUX_MAX_EXECVE_ARGS:
            truncated = True
        replacements = sum(count for _, _, count in ordered)
        blob["execve"] = {
            "argc": argc,
            "argv": [text for _, text, _ in ordered],
            "replacements": replacements,
            "truncated": truncated,
        }
    proctitle_match = _AUDIT_PROCTITLE.search(full_log)
    if proctitle_match is not None and proctitle_match.group(1):
        try:
            raw_title = bytes.fromhex(proctitle_match.group(1))
        except ValueError:
            raw_title = b""
        title = raw_title.decode("utf-8", errors="replace")
        blob["proctitle"] = {
            "cmdline": " ".join(title.split("\x00")).strip() or None,
            "replacements": title.count("�"),
        }
    paths: list[tuple[int, str]] = []
    for path in _AUDIT_PATH.finditer(full_log):
        try:
            paths.append((int(path.group(1)), path.group(2)))
        except ValueError:
            continue
    paths.sort(key=lambda item: item[0])
    # Empty names (unresolvable fds, sockets) carry no typed file: the
    # pinned schema requires ``file.name``, so they never become the
    # event path (the mapper raises without a non-empty PATH instead).
    blob["paths"] = [name for _, name in paths if name]
    cwd_match = _AUDIT_CWD.search(full_log)
    if cwd_match is not None:
        blob["cwd"] = cwd_match.group(1)
    saddr_match = _AUDIT_SADDR.search(full_log)
    if saddr_match is not None:
        try:
            port = int(saddr_match.group(3))
        except ValueError:
            port = None
        blob["saddr"] = {
            "fam": saddr_match.group(1),
            "ip": saddr_match.group(2),
            "port": port if port is not None and 0 <= port <= 65535 else None,
        }
    return blob


def _audit_users(audit: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return ``(actor, effective)`` users, honouring unset auid."""
    auid = _str(audit.get("auid"))
    if auid == _AUDITD_UNSET_AUID:
        auid = None
    return auid or _str(audit.get("uid")), _str(audit.get("euid")) or _str(
        audit.get("uid")
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

    The command line rebuilds from the EXECVE record joined by audit
    serial (hex decoded via :func:`decode_audit_hex`, counted), then
    ``audit.execve.a0..aN``, then the PROCTITLE record, then
    ``audit.command``. ``audit.exe`` is the image, ``audit.pid`` the
    pid, ``audit.auid`` the actor and ``audit.euid`` the effective
    user; an ``auid`` of 4294967295 means unset and falls back to
    ``uid``. Non-execve SYSCALL records without an image and without
    a command count as unmapped.
    """
    audit = fields.get("audit")
    if not isinstance(audit, dict):
        raise ValueError("audit record has no audit block")
    audit_type = _str(audit.get("type"))
    if audit_type != "SYSCALL":
        raise ValueError(f"auditd record type {audit_type!r} has no typed mapping")
    full_log = _str(source.get("full_log")) or ""
    blob = _parse_audit_blob(full_log)
    replacements = 0
    command: str | None = None
    if blob["execve"] is not None and blob["execve"]["argv"]:
        command = " ".join(blob["execve"]["argv"])
        replacements += blob["execve"]["replacements"]
    if command is None:
        raw_execve = audit.get("execve")
        parts: list[str] = []
        if isinstance(raw_execve, dict):
            ordered: list[tuple[int, str]] = []
            for key, value in raw_execve.items():
                if key == "argc":
                    continue
                index = _int(key[1:] if key.startswith("a") else key)
                raw_text = value if isinstance(value, str) else _str(value)
                if index is not None and raw_text is not None:
                    text, count = decode_audit_hex(raw_text)
                    replacements += count
                    ordered.append((index, text))
            parts = [text for _, text in sorted(ordered)]
        if parts:
            command = " ".join(parts)
    if command is None and blob["proctitle"] is not None:
        command = blob["proctitle"]["cmdline"]
        replacements += blob["proctitle"]["replacements"]
    if command is None:
        command = _str(audit.get("command"))
    unmapped: dict[str, Any] = {}
    command = _cap_typed(command, unmapped, "wazuh.audit_command_truncated")
    exe = _cap_typed(_str(audit.get("exe")), unmapped, "wazuh.audit_exe_truncated")
    if command is None and exe is None:
        raise ValueError("audit record has no command or exe")
    invoked, effective = _audit_users(audit)
    invoked = _cap_typed(invoked, unmapped, "wazuh.audit_actor_truncated")
    effective = _cap_typed(effective, unmapped, "wazuh.audit_user_truncated")
    for key in ("type", "id", "arch", "syscall", "success", "tty", "session", "key"):
        value = audit.get(key)
        if _str(value) is not None:
            unmapped[f"audit.{key}"] = value
    if blob["serial"] is not None:
        unmapped["linux.serial"] = blob["serial"]
    if blob["syscall"] is not None and blob["syscall"]["name"] is not None:
        unmapped["linux.syscall"] = blob["syscall"]["name"]
    if blob["time_ms"] is not None and blob["time_ms"] != time_ms:
        unmapped["linux.audit_time_ms"] = blob["time_ms"]
    if replacements:
        unmapped["linux.hex_replacements"] = replacements
    if blob["execve"] is not None and blob["execve"]["truncated"]:
        unmapped["linux.execve_truncated"] = True
    if blob["mismatch"]:
        unmapped["linux.serial_mismatch"] = True
    if blob["cwd"] is not None:
        unmapped["linux.cwd"] = blob["cwd"]
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
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _map_audit_file(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> FileSystemActivity:
    """Map a file-operation auditd SYSCALL to File Activity (1001).

    The syscall name (``SYSCALL=<name>`` decode line) selects the
    activity; the PATH records joined by serial supply the path (item
    order, first wins; a rename keeps the second path in
    ``unmapped``). Failed accesses (``success=no``) still emit: the
    attempt is the signal. Records without a syscall name or without
    a path count as unmapped.
    """
    audit = fields.get("audit")
    if not isinstance(audit, dict):
        raise ValueError("audit record has no audit block")
    full_log = _str(source.get("full_log")) or ""
    blob = _parse_audit_blob(full_log)
    name = blob["syscall"]["name"] if blob["syscall"] is not None else None
    if name is None or name not in _LINUX_FILE_ACTIVITIES:
        raise ValueError(f"auditd syscall {name!r} is not a mapped file operation")
    # ``*at`` syscalls list the dirfd (``/``) first and the target
    # later; the target is the last non-trivial path. A lone ``/``
    # names only the directory fd, so the record stays unmapped.
    candidates = [item for item in blob["paths"] if item not in ("/", ".")]
    if not candidates:
        raise ValueError("auditd file record has no usable PATH")
    unmapped: dict[str, Any] = {}
    path = _cap_typed(candidates[-1], unmapped, "wazuh.file_path_truncated")
    assert path is not None
    invoked, _ = _audit_users(audit)
    invoked = _cap_typed(invoked, unmapped, "wazuh.file_actor_truncated")
    for key in ("type", "id", "arch", "syscall", "success", "exit", "key"):
        value = audit.get(key)
        if _str(value) is not None:
            unmapped[f"audit.{key}"] = value
    if blob["serial"] is not None:
        unmapped["linux.serial"] = blob["serial"]
    unmapped["linux.syscall"] = name
    if name in ("rename", "renameat", "renameat2"):
        old = next((item for item in candidates if item != path), None)
        if old is not None:
            unmapped["linux.old_path"] = old
    if blob["mismatch"]:
        unmapped["linux.serial_mismatch"] = True
    if blob["cwd"] is not None:
        unmapped["linux.cwd"] = blob["cwd"]
    pid = _int(audit.get("pid"))
    exe = _cap_typed(_str(audit.get("exe")), unmapped, "wazuh.file_exe_truncated")
    return FileSystemActivity(
        time=time_ms,
        activity_id=_LINUX_FILE_ACTIVITIES[name],
        actor=Actor(
            user=User(name=invoked) if invoked is not None else None,
            process=(
                Process(pid=pid, name=exe.rsplit("/", 1)[-1] if exe else None)
                if pid is not None or exe is not None
                else None
            ),
        ),
        device=device,
        file=File(path=path, type="Unknown", type_id=0),
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _map_audit_net(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> NetworkActivity:
    """Map a ``connect`` auditd SYSCALL to Network Activity (4001).

    The peer comes from the decoded ``SADDR={...}`` line (the
    ``SOCKADDR`` record never reaches ``data.audit``); success=yes is
    activity 1 Open, anything else activity 4 Fail. ``socket()``
    syscalls carry no address and stay unmapped. Follows the Sysmon 3
    precedent: no ``action`` field, ``host`` profile only.
    """
    audit = fields.get("audit")
    if not isinstance(audit, dict):
        raise ValueError("audit record has no audit block")
    full_log = _str(source.get("full_log")) or ""
    blob = _parse_audit_blob(full_log)
    if blob["saddr"] is None or blob["saddr"]["ip"] is None:
        raise ValueError("auditd connect record has no decoded peer address")
    success = _str(audit.get("success"))
    activity_id = 1 if success == "yes" else 4
    unmapped: dict[str, Any] = {}
    invoked, _ = _audit_users(audit)
    invoked = _cap_typed(invoked, unmapped, "wazuh.net_actor_truncated")
    pid = _int(audit.get("pid"))
    exe = _cap_typed(_str(audit.get("exe")), unmapped, "wazuh.net_exe_truncated")
    peer_ip = _cap_typed(blob["saddr"]["ip"], unmapped, "wazuh.peer_ip_truncated")
    for key in ("type", "id", "arch", "syscall", "success", "exit", "key"):
        value = audit.get(key)
        if _str(value) is not None:
            unmapped[f"audit.{key}"] = value
    if blob["serial"] is not None:
        unmapped["linux.serial"] = blob["serial"]
    unmapped["linux.syscall"] = "connect"
    if blob["saddr"]["fam"] is not None:
        unmapped["linux.saddr_fam"] = blob["saddr"]["fam"]
    if blob["mismatch"]:
        unmapped["linux.serial_mismatch"] = True
    return NetworkActivity(
        time=time_ms,
        activity_id=activity_id,
        actor=Actor(
            user=User(name=invoked) if invoked is not None else None,
            process=(
                Process(pid=pid, name=exe.rsplit("/", 1)[-1] if exe else None)
                if pid is not None or exe is not None
                else None
            ),
        ),
        device=device,
        dst_endpoint=Endpoint(ip=peer_ip, port=blob["saddr"]["port"]),
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _map_audit_session(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> Authentication:
    """Map PAM/accounting audit records to Authentication (3002).

    ``USER_AUTH`` (``op=PAM:authentication``) is activity 1 Logon with
    success from ``res=``; ``USER_START`` and ``LOGIN`` are activity 1
    Logon Success (a session started / a login session gained its
    auid); ``USER_END`` is activity 2 Logoff Success. ``USER_ACCT``
    (accounting) and ``CRED_ACQ``/``CRED_DISP``/``CRED_REFR``
    (credential housekeeping) have no class in the pinned schema and
    stay counted as unmapped. Cron sessions are tagged
    ``unmapped["linux.cron"]`` so a later step can ignore them. The
    pinned 1.9.0 ``authentication`` event has no typed slot for the
    PAM service or terminal, so those land in ``unmapped``.
    """
    audit = fields.get("audit")
    if not isinstance(audit, dict):
        raise ValueError("audit record has no audit block")
    audit_type = _str(audit.get("type"))
    full_log = _str(source.get("full_log")) or ""
    username: str | None = None
    activity_id = 1
    status, status_id = "Success", 1
    unmapped: dict[str, Any] = {}
    acct_match = _AUDIT_ACCT.search(full_log)
    res_match = _AUDIT_RES.search(full_log)
    result = res_match.group(1) if res_match else _str(audit.get("res"))
    if audit_type == "USER_AUTH":
        if result is not None and result != "success":
            status, status_id = "Failure", 2
        username = acct_match.group(1) if acct_match else _str(audit.get("acct"))
    elif audit_type == "USER_START":
        username = acct_match.group(1) if acct_match else _str(audit.get("acct"))
    elif audit_type == "USER_END":
        activity_id = 2
        username = acct_match.group(1) if acct_match else _str(audit.get("acct"))
    elif audit_type == "LOGIN":
        auid_match = _AUDIT_AUID_OF.search(full_log)
        auid = auid_match.group(1) if auid_match else None
        if auid is None or auid.lower() in ("unset", "4294967295", "-1"):
            auid = None
        if auid is None:
            uid_match = _AUDIT_UID_OF.search(full_log)
            auid = uid_match.group(1) if uid_match else None
        username = auid or _str(audit.get("uid"))
    else:
        raise ValueError(f"auditd record type {audit_type!r} has no typed mapping")
    username, capped = _linux_user(username)
    unmapped.update(capped)
    if username is None:
        raise ValueError(f"auditd {audit_type} record has no user")
    exe_match = _AUDIT_EXE_MSG.search(full_log)
    exe = _cap_typed(
        exe_match.group(1).strip('"') if exe_match else _str(audit.get("exe")),
        unmapped,
        "wazuh.session_exe_truncated",
    )
    actor_process = None
    if exe is not None:
        actor_process = Process(
            pid=_int(audit.get("pid")), name=exe.rsplit("/", 1)[-1] or None
        )
    if "terminal=cron" in full_log:
        unmapped["linux.cron"] = True
    if exe is not None:
        unmapped["linux.exe"] = exe
    blob_serial = _AUDIT_HEAD.search(full_log)
    if blob_serial is not None:
        unmapped["linux.serial"] = blob_serial.group(3)
    user = User(name=username)
    return Authentication(
        time=time_ms,
        activity_id=activity_id,
        status=status,
        status_id=status_id,
        user=user,
        actor=Actor(user=User(name=username), process=actor_process),
        device=device,
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _map_audit_user_cmd(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> ProcessActivity:
    """Map a ``USER_CMD`` (sudo) audit record to Process Activity (1007).

    The command is always hex-encoded (``cmd=<hex>``); the invoking
    user comes from the decoded ``UID=`` (the audit ``uid`` is the
    target). ``cwd`` lands in ``unmapped``.
    """
    audit = fields.get("audit")
    if not isinstance(audit, dict):
        raise ValueError("audit record has no audit block")
    full_log = _str(source.get("full_log")) or ""
    cmd_match = _AUDIT_CMD.search(full_log)
    command: str | None = None
    replacements = 0
    if cmd_match is not None:
        try:
            raw_cmd = bytes.fromhex(cmd_match.group(1))
        except ValueError:
            raw_cmd = b""
        decoded = raw_cmd.decode("utf-8", errors="replace")
        replacements = decoded.count("�")
        command = decoded or None
    unmapped: dict[str, Any] = {}
    command = _cap_typed(command, unmapped, "wazuh.user_cmd_truncated")
    if command is None:
        raise ValueError("USER_CMD record has no decodable command")
    uid_match = _AUDIT_UID_OF.search(full_log)
    invoking = uid_match.group(1) if uid_match else _str(audit.get("uid"))
    if invoking is None or invoking.lower() in ("unset", "4294967295"):
        invoking = None
    invoking = _cap_typed(invoking, unmapped, "wazuh.user_cmd_actor_truncated")
    exe_match = _AUDIT_EXE_MSG.search(full_log)
    exe = _cap_typed(
        exe_match.group(1).strip('"') if exe_match else _str(audit.get("exe")),
        unmapped,
        "wazuh.user_cmd_exe_truncated",
    )
    cwd_match = _AUDIT_CWD_MSG.search(full_log)
    if cwd_match is not None:
        unmapped["linux.cwd"] = cwd_match.group(1)
    if replacements:
        unmapped["linux.hex_replacements"] = replacements
    blob_serial = _AUDIT_HEAD.search(full_log)
    if blob_serial is not None:
        unmapped["linux.serial"] = blob_serial.group(3)
    argv0 = command.split()[0]
    return ProcessActivity(
        time=time_ms,
        activity_id=1,
        actor=Actor(user=User(name=invoking) if invoking is not None else None),
        device=device,
        process=Process(
            pid=_int(audit.get("pid")),
            name=argv0.rsplit("/", 1)[-1] or None,
            cmd_line=command,
            file=(
                File(path=exe, type="Executable File", type_id=8)
                if exe is not None
                else None
            ),
        ),
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _map_pam(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> Authentication:
    """Map PAM session (and auth-failure) lines to Authentication (3002).

    ``session opened`` is activity 1 Logon Success, ``session
    closed`` activity 2 Logoff Success; the ``by <user>`` opener
    becomes the actor. A ``pam_unix(...:auth): authentication
    failure`` line is activity 1 Logon Failure when it names a user.
    The pinned schema has no session class for these (the 1.9.0
    ``authorize_session`` activities are privilege/group assignments),
    and Logon/Logoff describe exactly a session starting and ending.
    Cron sessions (``CRON`` program) are tagged
    ``unmapped["linux.cron"]`` so a later step can ignore them.
    """
    full_log = _str(source.get("full_log")) or ""
    unmapped: dict[str, Any] = {}
    username: str | None = None
    actor_name: str | None = None
    session_match = _PAM_SESSION.search(full_log)
    if session_match is not None:
        activity_id = 1 if session_match.group(1) == "opened" else 2
        status, status_id = "Success", 1
        username = session_match.group("user")
        actor_name = session_match.group("by")
    elif "authentication failure" in full_log:
        activity_id = 1
        status, status_id = "Failure", 2
        for key in ("ruser", "logname"):
            hit = re.search(rf"\b{key}=(\S+)", full_log)
            if hit is not None and hit.group(1):
                username = hit.group(1)
                break
        username = username or _str(fields.get("srcuser"))
    else:
        raise ValueError("pam record is not a session or auth-failure line")
    if username is None:
        username = _str(fields.get("srcuser")) or _str(fields.get("dstuser"))
    if actor_name is None:
        actor_name = _str(fields.get("srcuser"))
    actor_name = _cap_typed(actor_name, unmapped, "wazuh.pam_actor_truncated")
    username, capped = _linux_user(username)
    unmapped.update(capped)
    if username is None:
        raise ValueError("pam record has no user")
    predecoder = source.get("predecoder")
    program = predecoder.get("program_name") if isinstance(predecoder, dict) else None
    if program == "CRON" or "(cron:session)" in full_log:
        unmapped["linux.cron"] = True
        actor_name = actor_name or username
    user = User(name=username)
    return Authentication(
        time=time_ms,
        activity_id=activity_id,
        status=status,
        status_id=status_id,
        user=user,
        actor=Actor(user=User(name=actor_name) if actor_name is not None else None),
        device=device,
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _map_su(
    *,
    source: dict[str, Any],
    fields: dict[str, Any],
    decoder: str,
    uid: str,
    time_ms: int,
    device: Device | None,
) -> Authentication:
    """Map an ``su`` invocation line to Authentication (3002, Logon).

    ``(to <target>) <invoker> on <tty>`` names the target as the
    subject and the invoker as the actor; the line reports a completed
    invocation, so status is Success. The tty has no typed slot and
    lands in ``unmapped``.
    """
    full_log = _str(source.get("full_log")) or ""
    match = _SU_LINE.search(full_log)
    target = match.group("target") if match else _str(fields.get("dstuser"))
    invoker = match.group("invoker") if match else _str(fields.get("srcuser"))
    target, capped = _linux_user(target)
    unmapped: dict[str, Any] = dict(capped)
    invoker = _cap_typed(invoker, unmapped, "wazuh.su_invoker_truncated")
    if match is not None:
        unmapped["linux.tty"] = match.group("tty")
    if target is None:
        raise ValueError("su record has no target user")
    return Authentication(
        time=time_ms,
        activity_id=1,
        status="Success",
        status_id=1,
        user=User(name=target),
        actor=Actor(user=User(name=invoker) if invoker is not None else None),
        device=device,
        metadata=_metadata(uid, decoder, device),
        raw_data=_capped_raw(source, unmapped),
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
    unmapped: dict[str, Any] = {}
    path = _cap_typed(
        _str(syscheck.get("path")), unmapped, "wazuh.syscheck_path_truncated"
    )
    if path is None:
        raise ValueError("syscheck record has no path")
    event = (_str(syscheck.get("event")) or "").lower()
    fingerprints: list[Fingerprint] = []
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
                        algorithm=caption,
                        algorithm_id=algorithm_id,
                        value=_cap_typed(
                            text, unmapped, "wazuh.syscheck_digest_truncated"
                        ),
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
        raw_data=_capped_raw(source, unmapped),
        unmapped=unmapped,
    )


def _audit_route(source: dict[str, Any], fields: dict[str, Any]) -> str:
    """Return the auditd mapping route for one document.

    ``exec`` for execve SYSCALLs (Process Activity), ``net`` for
    ``connect`` with a decoded peer (Network Activity), ``file`` for
    file-operation syscalls with PATH records (File Activity),
    ``session`` for PAM/accounting records, ``user-cmd`` for sudo
    invocations, and ``unmapped`` for everything else (companions,
    ``socket()``, process bookkeeping, BPF, services, credentials).
    """
    audit = fields.get("audit")
    audit_type = _str(audit.get("type")) if isinstance(audit, dict) else None
    if audit_type != "SYSCALL":
        if audit_type in _AUDIT_SESSION_TYPES:
            return "session" if audit_type != "USER_CMD" else "user-cmd"
        return "unmapped"
    full_log = _str(source.get("full_log")) or ""
    name_match = _AUDIT_SYSCALL_NAME.search(full_log)
    name = name_match.group(1) if name_match else None
    if name is None:
        number = _str(audit.get("syscall")) if isinstance(audit, dict) else None
        name = {"59": "execve", "42": "connect", "41": "socket"}.get(number or "")
    if name == "execve":
        return "exec"
    if name == "connect":
        return "net"
    if name is not None and name in _LINUX_FILE_ACTIVITIES:
        return "file"
    return "unmapped"


def _map_event(
    source: dict[str, Any],
    uid: str,
    *,
    override_time_ms: int | None = None,
) -> tuple[OcsfEvent | None, tuple[str, str | None] | None]:
    """Map one Wazuh document to its underlying event.

    Returns ``(event, None)`` when the decoder maps, else
    ``(None, (decoder, rule_id))`` for the unmapped counter. Records
    missing a required typed attribute (no sshd user, no sudo command,
    no syscheck path) count as unmapped rather than raising.
    ``override_time_ms`` carries the log-line event time for the raw
    archive path; the alert/archive hit paths keep the manager
    timestamp their cursors sort on. Far-future ISO timestamps past
    2100-01-01 UTC still map (via :func:`parse_wazuh_time_unbounded`)
    so the live poll can count them as ``future_dated`` and withhold
    checkpoint progress; every other hostile time stays unmapped.
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
    if override_time_ms is not None:
        time_ms = override_time_ms
    else:
        raw_stamp = source.get("timestamp") or source.get("@timestamp")
        try:
            time_ms = parse_wazuh_time(raw_stamp)
        except ValueError, TypeError:
            try:
                time_ms = _far_future_ms(raw_stamp)
            except ValueError, TypeError:
                return None, (decoder, rule_id)
    device_unmapped: dict[str, Any] = {}
    device = _device(source, device_unmapped)
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
        elif decoder == "pam":
            event = _map_pam(
                source=source,
                fields=fields,
                decoder=decoder,
                uid=uid,
                time_ms=time_ms,
                device=device,
            )
        elif decoder == "su":
            event = _map_su(
                source=source,
                fields=fields,
                decoder=decoder,
                uid=uid,
                time_ms=time_ms,
                device=device,
            )
        elif decoder == "auditd":
            route = _audit_route(source, fields)
            if route == "exec":
                event = _map_audit(
                    source=source,
                    fields=fields,
                    decoder=decoder,
                    uid=uid,
                    time_ms=time_ms,
                    device=device,
                )
            elif route == "net":
                event = _map_audit_net(
                    source=source,
                    fields=fields,
                    decoder=decoder,
                    uid=uid,
                    time_ms=time_ms,
                    device=device,
                )
            elif route == "file":
                event = _map_audit_file(
                    source=source,
                    fields=fields,
                    decoder=decoder,
                    uid=uid,
                    time_ms=time_ms,
                    device=device,
                )
            elif route == "session":
                event = _map_audit_session(
                    source=source,
                    fields=fields,
                    decoder=decoder,
                    uid=uid,
                    time_ms=time_ms,
                    device=device,
                )
            elif route == "user-cmd":
                event = _map_audit_user_cmd(
                    source=source,
                    fields=fields,
                    decoder=decoder,
                    uid=uid,
                    time_ms=time_ms,
                    device=device,
                )
            else:
                return None, (decoder, rule_id)
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
    if device_unmapped and event is not None:
        event.unmapped.update(device_unmapped)
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
    """Build the Detection Finding (2004) for one Wazuh alert.

    The rule description becomes the finding title (and analytic
    name/desc), so it is capped at :data:`WAZUH_RAW_DATA_CAP` with the
    original length in ``unmapped``.
    """
    rule_id = rule.get("id")
    unmapped: dict[str, Any] = {}
    raw_description = _str(rule.get("description")) or f"Wazuh rule {rule_id}"
    description = _cap_typed(raw_description, unmapped, "wazuh.description_truncated")
    assert description is not None
    level = _int(rule.get("level"))
    severity_id, severity = severity_for_level(level if level is not None else 0)
    groups = _groups(rule)
    category = _cap_typed(
        ",".join(groups) if groups else None, unmapped, "wazuh.category_truncated"
    )
    firedtimes = _int(rule.get("firedtimes"))
    analytic = Analytic(
        name=description,
        uid=str(rule_id) if rule_id is not None else None,
        desc=description,
        category=category,
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
        raw_data=_capped_raw(source, unmapped),
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
    without a parseable time raise ``ValueError``; far-future ISO
    timestamps past 2100-01-01 UTC still map so the live poll counts
    them as ``future_dated`` instead of unmapped.
    """
    raw_source = hit.get("_source")
    if not isinstance(raw_source, dict):
        raise ValueError("wazuh hit has no _source")
    clean_source, source_bad = _sanitize_value(dict(raw_source))
    assert isinstance(clean_source, dict)
    source = clean_source
    rule = _rule(source)
    alert_id = _str(source.get("id"))
    if alert_id is None:
        raise ValueError("wazuh alert has no id")
    raw_stamp = source.get("timestamp") or source.get("@timestamp")
    try:
        time_ms = parse_wazuh_time(raw_stamp)
    except ValueError, TypeError:
        time_ms = _far_future_ms(raw_stamp)
    decoder_block = source.get("decoder")
    decoder = (
        _str(decoder_block.get("name"))
        if isinstance(decoder_block, dict)
        else _str(decoder_block)
    ) or "unknown"
    finding_unmapped: dict[str, Any] = {}
    device = _device(source, finding_unmapped)
    event, unmapped_key = _map_event(source, f"{alert_id}#event")
    finding = _build_finding(source, rule, alert_id, time_ms, device, decoder, event)
    if finding_unmapped:
        finding.unmapped.update(finding_unmapped)
    if source_bad:
        finding.unmapped["wazuh.text_sanitized"] = True
        if event is not None:
            event.unmapped["wazuh.text_sanitized"] = True
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
    raw_source = hit.get("_source")
    if not isinstance(raw_source, dict):
        raise ValueError("wazuh hit has no _source")
    clean_source, source_bad = _sanitize_value(dict(raw_source))
    assert isinstance(clean_source, dict)
    source = clean_source
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
    if source_bad:
        event.unmapped["wazuh.text_sanitized"] = True
    return event, None


def parse_linux_time(doc: dict[str, Any]) -> int:
    """Return one archive document's event time (UTC epoch ms).

    The time comes from the log line, never the manager receive
    time: audit documents use the kernel ``msg=audit(<time>:<serial>)``
    stamp; syslog lines use their leading timestamp (ISO-8601 from
    auth.log, ``Mon dd HH:MM:SS`` from journald with the year from the
    manager timestamp, rolling back a year when the line would land
    more than a day in the future). Documents without a parseable
    line fall back to the manager ``timestamp``/``@timestamp``.
    """
    from corvus.normalize.ocsf import MAX_TIME_MS, MIN_TIME_MS

    def _check_linux_ms(ms: int) -> int:
        if ms < MIN_TIME_MS:
            raise ValueError(f"linux time {ms} is before 2000-01-01 UTC")
        if ms > MAX_TIME_MS:
            raise ValueError(f"linux time {ms} is after 2100-01-01 UTC")
        return ms

    full_log = doc.get("full_log")
    manager = doc.get("timestamp") or doc.get("@timestamp")
    if isinstance(full_log, str):
        head = _AUDIT_HEAD.search(full_log)
        if head is not None:
            try:
                number = float(head.group(2))
            except ValueError:
                pass
            else:
                if not math.isfinite(number):
                    raise ValueError(
                        f"linux audit time {head.group(2)!r} is not finite"
                    )
                try:
                    ms = int(number * 1000)
                except (OverflowError, ValueError) as exc:
                    raise ValueError(
                        f"linux audit time {head.group(2)!r} is not a time"
                    ) from exc
                return _check_linux_ms(ms)
        iso = _SYSLOG_ISO.match(full_log)
        if iso is not None:
            return parse_wazuh_time(iso.group(1))
        short = _SYSLOG_SHORT.match(full_log)
        if short is not None and _MONTHS.get(short.group(1)) is not None:
            manager_ms = parse_wazuh_time(manager)
            year = datetime.fromtimestamp(manager_ms / 1000, UTC).year
            moment = datetime(
                year,
                _MONTHS[short.group(1)],
                int(short.group(2)),
                int(short.group(3)),
                int(short.group(4)),
                int(short.group(5)),
                tzinfo=UTC,
            )
            try:
                moment_ms = int(moment.timestamp() * 1000)
            except (OverflowError, OSError, ValueError) as exc:
                raise ValueError("linux syslog time is not a time") from exc
            if moment_ms > manager_ms + 86400000:
                moment = moment.replace(year=year - 1)
                try:
                    moment_ms = int(moment.timestamp() * 1000)
                except (OverflowError, OSError, ValueError) as exc:
                    raise ValueError("linux syslog time is not a time") from exc
            return _check_linux_ms(moment_ms)
    return parse_wazuh_time(manager)


def _linux_dedupe_body(doc: dict[str, Any]) -> str | None:
    """Return the canonical dedup body for one archive document."""
    full_log = doc.get("full_log")
    if not isinstance(full_log, str) or not full_log:
        return None
    iso = _SYSLOG_ISO.match(full_log)
    if iso is not None:
        return full_log[iso.end() :]
    short = _SYSLOG_SHORT.match(full_log)
    if short is not None:
        return full_log[short.end() :]
    return None


def linux_dedup_key(doc: dict[str, Any]) -> str:
    """Return the deduplication key for one Linux archive document.

    The same event arrives twice (``auth.log`` and ``journald``
    copies on one agent share program, pid and message but carry
    different receive timestamps): syslog lines key on
    ``agent + canonical body`` (leading timestamp and hostname
    stripped), so both copies share a key. Audit records key on
    ``agent + serial``: a SYSCALL and its EXECVE/CWD/PATH/PROCTITLE
    companions share the serial and collapse to one event, while
    session records (``USER_AUTH``, ``LOGIN``, ...) keep their type
    in the key so distinct records never collapse. Documents without
    a serial or a syslog body fall back to a hash of the log line.
    This function never raises.
    """
    try:
        agent = doc.get("agent")
        agent_id = (
            agent.get("id") or agent.get("name") if isinstance(agent, dict) else None
        ) or "unknown"
        data = doc.get("data")
        audit = data.get("audit") if isinstance(data, dict) else None
        serial: str | None = None
        audit_type: str | None = None
        if isinstance(audit, dict):
            audit_type = _str(audit.get("type"))
            serial = _str(audit.get("id"))
        full_log = doc.get("full_log")
        if serial is None and isinstance(full_log, str):
            head = _AUDIT_HEAD.search(full_log)
            if head is not None:
                serial = head.group(3)
        if serial is not None and audit_type is not None:
            if audit_type == "SYSCALL" or audit_type in _AUDIT_COMPANIONS:
                return f"audit:{agent_id}:{serial}"
            return f"audit:{agent_id}:{serial}:{audit_type}"
        if serial is not None:
            return f"audit:{agent_id}:{serial}"
        body = _linux_dedupe_body(doc)
        if body is not None:
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
            return f"log:{agent_id}:{digest}"
        if isinstance(full_log, str) and full_log:
            digest = hashlib.sha256(full_log.encode("utf-8")).hexdigest()[:16]
            return f"log:{agent_id}:{digest}"
        digest = hashlib.sha256(
            json.dumps(doc, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        return f"doc:{agent_id}:{digest}"
    except Exception:
        return "doc:unhashable"


def map_linux_doc(
    doc: dict[str, Any],
) -> tuple[
    DetectionFinding | None, OcsfEvent | None, tuple[str, str | None] | None, str
]:
    """Map one raw Linux archive document.

    ``doc`` is the archive JSON object itself (not an OpenSearch
    hit). Returns ``(finding, event, unmapped_key, dedupe_key)``:
    ``finding`` is built only when the document carries a ``rule``
    block; ``event`` is None with ``unmapped_key`` set to
    ``(decoder, rule id)`` when the decoder has no typed mapping;
    ``dedupe_key`` (see :func:`linux_dedup_key`) is stable across the
    auth.log/journald copies and across SYSCALL companion documents.
    The event uid derives from the dedupe key, so loading the same
    document twice yields the same uid.
    """
    if not isinstance(doc, dict):
        raise ValueError("linux document is not an object")
    clean_doc, doc_bad = _sanitize_value(dict(doc))
    assert isinstance(clean_doc, dict)
    doc = clean_doc
    dedupe = linux_dedup_key(doc)
    decoder_block = doc.get("decoder")
    decoder = (
        _str(decoder_block.get("name"))
        if isinstance(decoder_block, dict)
        else _str(decoder_block)
    ) or "unknown"
    rule = doc.get("rule")
    rule_id: str | None = None
    if isinstance(rule, dict) and rule.get("id") is not None:
        rule_id = str(rule.get("id"))
    try:
        time_ms = parse_linux_time(doc)
    except ValueError, TypeError:
        return None, None, (decoder, rule_id), dedupe
    event_uid = "lnx-" + hashlib.sha256(dedupe.encode("utf-8")).hexdigest()[:16]
    event, unmapped_key = _map_event(doc, event_uid, override_time_ms=time_ms)
    finding: DetectionFinding | None = None
    if isinstance(rule, dict) and rule.get("id") is not None:
        finding_uid = _str(doc.get("id")) or event_uid
        finding_unmapped: dict[str, Any] = {}
        finding = _build_finding(
            doc,
            rule,
            finding_uid,
            time_ms,
            _device(doc, finding_unmapped),
            decoder,
            event,
        )
        if finding_unmapped:
            finding.unmapped.update(finding_unmapped)
    if doc_bad:
        if event is not None:
            event.unmapped["wazuh.text_sanitized"] = True
        if finding is not None:
            finding.unmapped["wazuh.text_sanitized"] = True
    return finding, event, unmapped_key, dedupe
