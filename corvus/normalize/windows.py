"""Windows event normalizer: Sysmon, Security and Task Scheduler to OCSF.

Reads two third-party replay formats without copying their content:
``.evtx`` files via the ``evtx`` package (pyevtx-rs ``PyEvtxParser`` with
``records_json``) and OTRF JSON-lines members inside ``.zip`` / ``.tar.gz``
archives. :func:`iter_dataset_file` streams one OCSF event at a time while
filling a :class:`WindowsReadStats` (archives are never loaded fully into
memory); :func:`read_dataset_file` is a thin wrapper collecting the same
stream for tests. Every mapped record becomes one OCSF event carrying the
real Windows channel in ``metadata.log_name`` and an opaque
``metadata.uid`` (a truncated SHA-256 over the dataset-relative path plus
the record id, so ATT&CK ids in dataset file names can never leak into the
record).

Mappings (anything else raises :class:`UnmappedEvent` and the readers count
it per ``(channel, event id)``, never dropping it silently):

- Sysmon event 1 -> Process Activity (1007)
- Sysmon event 3 -> Network Activity (4001)
- Sysmon event 11 -> File System Activity (1001)
- Security 4624 / 4625 -> Authentication (3002), success / failure
- Security 4698 and Microsoft-Windows-TaskScheduler/Operational 106
  -> Scheduled Job Activity (1006)

All times become timezone-aware UTC (naive Windows timestamps are assumed
to be UTC); a mapped event whose time cannot be parsed is counted as
unmapped under its own ``(channel, event id)``.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser

from corvus.normalize.ocsf import (
    MIN_TIME_MS,
    PLACEHOLDERS,
    Actor,
    Authentication,
    Device,
    Endpoint,
    File,
    FileSystemActivity,
    Job,
    Metadata,
    NetworkActivity,
    OcsfEvent,
    Process,
    ProcessActivity,
    Product,
    ScheduledJobActivity,
    User,
)

__all__ = [
    "SECURITY_CHANNEL",
    "SYSMON_CHANNEL",
    "TASKSCHEDULER_CHANNEL",
    "UnmappedEvent",
    "WindowsReadResult",
    "WindowsReadStats",
    "extract_evtx_parts",
    "extract_flat_parts",
    "extract_json_parts",
    "extract_old_beat_parts",
    "extract_winlog_parts",
    "iter_dataset_file",
    "make_uid",
    "normalize_event",
    "parse_windows_time",
    "read_dataset_file",
    "read_evtx",
    "read_otrf_archive",
    "sanitize_record",
]

#: Real Windows channels, used verbatim as ``metadata.log_name``.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
TASKSCHEDULER_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"

#: Lowercased channel spellings seen in replay files -> canonical spelling.
#: Matching is case-insensitive; ``metadata.log_name`` always carries the
#: canonical spelling so downstream grouping stays deterministic.
_CHANNEL_ALIASES = {
    SYSMON_CHANNEL.lower(): SYSMON_CHANNEL,
    SECURITY_CHANNEL.lower(): SECURITY_CHANNEL,
    TASKSCHEDULER_CHANNEL.lower(): TASKSCHEDULER_CHANNEL,
}

#: Envelope keys of a flat record that are placed structurally (channel,
#: event id, host, time) and never belong in the per-event ``unmapped`` map.
_FLAT_ENVELOPE_KEYS = frozenset(
    {
        "Channel",
        "EventID",
        "EventIdx",
        "EventRecordID",
        "Computer",
        "Hostname",
        "TimeCreated",
        "UtcTime",
        "@timestamp",
    }
)

#: Envelope keys of the older winlogbeat layout (``log_name`` /
#: ``event_id`` with the payload nested under ``event_data``) that are
#: placed structurally. Every other top-level key is merged into the
#: mapper payload so it ends up typed or in ``unmapped``, never dropped.
_OLD_BEAT_ENVELOPE_KEYS = frozenset(
    {
        "log_name",
        "event_id",
        "record_number",
        "computer_name",
        "@timestamp",
    }
)

#: Envelope keys of the newer nested ``winlog`` layout (``winlog.channel`` /
#: ``winlog.event_id`` with the payload under ``winlog.event_data``).
_WINLOG_ENVELOPE_KEYS = frozenset(
    {
        "channel",
        "event_id",
        "record_id",
        "computer_name",
        "event_data",
    }
)

#: Winlogbeat/Logstash ingestion fields that carry dataset file paths.
#: Stripped from ``raw_data`` and from the per-event ``unmapped`` map so a
#: source file name (which may encode an ATT&CK technique id) never enters
#: the OCSF record.
INGESTION_KEYS = frozenset({"log", "path", "log.file.path", "@metadata"})


class UnmappedEvent(Exception):
    """A record has no mapping; counted per ``(channel, event id)``."""

    def __init__(self, channel: str, event_id: int) -> None:
        super().__init__(f"no mapping for channel {channel!r} event {event_id}")
        self.key = (channel, event_id)


@dataclass
class WindowsReadStats:
    """Mutable counts filled while streaming a replay file.

    Pass your own instance to :func:`iter_dataset_file` to read the counts
    after the iterator is exhausted; the events themselves stream one at a
    time so the caller never holds a whole dataset in memory.
    """

    unmapped: dict[tuple[str, int], int] = field(default_factory=dict)
    unsupported: int = 0

    def count(self, channel: str, event_id: int) -> None:
        """Add one unmapped record under ``(channel, event id)``."""
        key = (channel, event_id)
        self.unmapped[key] = self.unmapped.get(key, 0) + 1


@dataclass
class WindowsReadResult:
    """One replay file read: mapped events plus what was not mapped."""

    events: list[OcsfEvent] = field(default_factory=list)
    unmapped: dict[tuple[str, int], int] = field(default_factory=dict)
    unsupported: int = 0

    def count(self, channel: str, event_id: int) -> None:
        """Add one unmapped record under ``(channel, event id)``."""
        key = (channel, event_id)
        self.unmapped[key] = self.unmapped.get(key, 0) + 1


def make_uid(dataset_rel: str, record_id: object) -> str:
    """Return the opaque, stable event id for one record.

    A truncated SHA-256 over the dataset-relative path plus the record id:
    the same input always yields the same 16-hex-char id, distinct records
    yield distinct ids, and the file name cannot be recovered from it.
    """
    seed = f"{dataset_rel}#{record_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return ``record`` without file-path ingestion fields."""
    return {k: v for k, v in record.items() if k not in INGESTION_KEYS}


def parse_windows_time(value: object) -> int:
    """Parse a Windows timestamp into UTC epoch milliseconds.

    Accepts aware and naive ``datetime`` objects (naive means UTC, matching
    Sysmon ``UtcTime``), epoch seconds or milliseconds, and strings: ISO
    8601 with ``Z``/offset or a space separator, ``YYYY-MM-DD HH:MM:SS[.fff]``
    and US ``M/D/YYYY H:MM:SS [AM/PM]``. Raises ``ValueError`` when the value
    is missing or lands before 2000-01-01 UTC.
    """
    if isinstance(value, bool):
        raise ValueError(f"cannot parse time from {value!r}")
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return _checked_ms(int(moment.timestamp() * 1000))
    if isinstance(value, int | float):
        number = float(value)
        ms = int(number) if number >= MIN_TIME_MS else int(number * 1000)
        return _checked_ms(ms)
    if isinstance(value, str):
        text = value.strip()
        if not text or not text[0].isdigit():
            raise ValueError(f"cannot parse time from {value!r}")
        zoned = text
        if zoned.endswith(("Z", "z")):
            zoned = zoned[:-1] + "+00:00"
        if zoned.endswith(" UTC"):
            zoned = zoned[:-4] + "+00:00"
        try:
            parsed = datetime.fromisoformat(zoned)
        except ValueError:
            parsed = _parse_non_iso(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return _checked_ms(int(parsed.timestamp() * 1000))
    raise ValueError(f"cannot parse time from {value!r}")


def _checked_ms(moment_ms: int) -> int:
    """Reject times before the 2000-01-01 UTC floor shared with OCSF."""
    if moment_ms < MIN_TIME_MS:
        raise ValueError(f"time {moment_ms} is before 2000-01-01 UTC")
    return moment_ms


def _parse_non_iso(text: str) -> datetime:
    """Parse the non-ISO spellings Windows producers emit."""
    for pattern in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(float(text), tz=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError(f"cannot parse time from {text!r}") from exc


def _text(value: object) -> str | None:
    """Return stripped text, or None for missing values and placeholders."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in PLACEHOLDERS:
        return None
    return text


def _port(value: object) -> int | None:
    """Coerce a port number, or None when it is not a valid port."""
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        return None
    return number if 0 <= number <= 65535 else None


def _pid(value: object) -> int | None:
    """Coerce a process id, or None when it is not a valid pid."""
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        return None
    return number if number >= 0 else None


def _coerce_event_id(value: object) -> int:
    """Coerce an event id; anything unusable becomes 0 (counted, not lost).

    Some producers render the id as an object with ``#text`` content;
    that spells the real id and counts under it, not under 0.
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, dict):
        text = value.get("#text", value.get("#attributes"))
        if isinstance(text, dict):
            return 0
        return _coerce_event_id(text)
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return 0


def _basename(path: str | None) -> str | None:
    """Return the file name of a Windows or POSIX path."""
    if path is None:
        return None
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None


def _split_account(text: str | None) -> tuple[str | None, str | None]:
    """Split ``DOMAIN\\user`` into ``(user, domain)``; bare names stay whole."""
    if text is None:
        return None, None
    account = text.strip()
    if "\\" in account:
        domain, _, user = account.partition("\\")
        return (user.strip() or None, domain.strip() or None)
    return (account or None, None)


@dataclass(frozen=True)
class _Ctx:
    """Per-record mapping context: identity, time, channel, host."""

    uid: str
    time_ms: int
    channel: str
    computer: str | None


def _product_name(channel: str) -> str:
    """Name the producing product: Sysmon emits its own channel."""
    return "Sysmon" if channel == SYSMON_CHANNEL else "Microsoft Windows"


def _metadata(ctx: _Ctx) -> Metadata:
    """Build the OCSF metadata envelope with the real Windows channel."""
    return Metadata(
        product=Product(name=_product_name(ctx.channel), vendor_name="Microsoft"),
        log_name=ctx.channel,
        uid=ctx.uid,
    )


def _device(ctx: _Ctx) -> Device | None:
    """Build the device object, or None when no host is known."""
    hostname = _text(ctx.computer)
    return Device(hostname=hostname) if hostname is not None else None


def _actor(
    name: str | None, domain: str | None, process: Process | None = None
) -> Actor | None:
    """Build the actor object, or None when neither user nor process is known."""
    if name is None and domain is None and process is None:
        return None
    user = None
    if name is not None or domain is not None:
        user = User(name=name, domain=domain)
    return Actor(user=user, process=process)


def _initiating_process(image: str | None, pid: int | None) -> Process | None:
    """Build the initiating process placed in ``actor.process``.

    The caller leaves ``ProcessGuid`` in the payload (it has no typed OCSF
    slot) so it lands in ``unmapped`` instead of being dropped.
    """
    if pid is None and image is None:
        return None
    return Process(
        pid=pid,
        name=_basename(image),
        file=File(path=image) if image is not None else None,
    )


#: Windows LogonType -> OCSF ``logon_type_id``. Windows 0 (System) is OCSF 1;
#: anything outside the Windows set maps to OCSF 99 (Other).
_WINDOWS_TO_OCSF_LOGON_TYPE = {
    0: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    7: 7,
    8: 8,
    9: 9,
    10: 10,
    11: 11,
}

#: Captions of the pinned OCSF 1.4.0 ``logon_type_id`` enum (``dictionary.json``
#: ``attributes.logon_type_id.enum`` in ``ocsf-schema`` tag ``v1.4.0``).
_LOGON_TYPE_CAPTIONS = {
    0: "Unknown",
    1: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "OS Service",
    7: "Unlock",
    8: "Network Cleartext",
    9: "New Credentials",
    10: "Remote Interactive",
    11: "Cached Interactive",
    12: "Cached Remote Interactive",
    13: "Cached Unlock",
    99: "Other",
}


def _logon_type_id(value: object) -> tuple[int | None, str | None]:
    """Map a Windows LogonType to ``(logon_type_id, logon_type)``.

    Returns ``(None, None)`` when the value is not a usable number; the
    original value always stays in the payload so it lands in ``unmapped``.
    """
    if isinstance(value, bool):
        return None, None
    try:
        number = int(str(value).strip())
    except (ValueError, TypeError):
        return None, None
    mapped = _WINDOWS_TO_OCSF_LOGON_TYPE.get(number, 99)
    return mapped, _LOGON_TYPE_CAPTIONS[mapped]


def _map_sysmon_process(fields: dict[str, Any], ctx: _Ctx) -> ProcessActivity:
    """Map Sysmon event 1 (process creation) to Process Activity."""
    image = _text(fields.pop("Image", None))
    pid = _pid(fields.pop("ProcessId", None))
    cmd_line = _text(fields.pop("CommandLine", None))
    parent_image = _text(fields.pop("ParentImage", None))
    parent_pid = _pid(fields.pop("ParentProcessId", None))
    user, domain = _split_account(_text(fields.pop("User", None)))
    fields.pop("UtcTime", None)
    parent: Process | None = None
    if parent_pid is not None or parent_image is not None:
        parent = Process(
            pid=parent_pid,
            name=_basename(parent_image),
            file=File(path=parent_image) if parent_image is not None else None,
        )
    process: Process | None = None
    if pid is not None or image is not None or cmd_line is not None:
        process = Process(
            pid=pid,
            name=_basename(image),
            cmd_line=cmd_line,
            file=File(path=image) if image is not None else None,
            parent_process=parent,
        )
    return ProcessActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(user, domain),
        process=process,
        unmapped=fields,
    )


def _map_sysmon_network(fields: dict[str, Any], ctx: _Ctx) -> NetworkActivity:
    """Map Sysmon event 3 (network connection) to Network Activity.

    Every payload key ends up typed or in ``unmapped``: the initiating
    process (``Image``/``ProcessId``) becomes ``actor.process`` while
    ``ProcessGuid``, ``Protocol`` and the hostname flags stay in
    ``unmapped`` (no typed OCSF slot).
    """
    src_ip = _text(fields.pop("SourceIp", None))
    src_port = _port(fields.pop("SourcePort", None))
    dst_ip = _text(fields.pop("DestinationIp", None))
    dst_port = _port(fields.pop("DestinationPort", None))
    image = _text(fields.pop("Image", None))
    pid = _pid(fields.pop("ProcessId", None))
    user, domain = _split_account(_text(fields.pop("User", None)))
    fields.pop("UtcTime", None)
    src: Endpoint | None = None
    if src_ip is not None or src_port is not None:
        src = Endpoint(ip=src_ip, port=src_port)
    dst: Endpoint | None = None
    if dst_ip is not None or dst_port is not None:
        dst = Endpoint(ip=dst_ip, port=dst_port)
    return NetworkActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(user, domain, _initiating_process(image, pid)),
        src_endpoint=src,
        dst_endpoint=dst,
        unmapped=fields,
    )


def _map_sysmon_file(fields: dict[str, Any], ctx: _Ctx) -> FileSystemActivity:
    """Map Sysmon event 11 (file creation) to File System Activity.

    The creating process (``Image``/``ProcessId``) becomes
    ``actor.process``; ``ProcessGuid`` stays in ``unmapped``.
    """
    target = _text(fields.pop("TargetFilename", None))
    image = _text(fields.pop("Image", None))
    pid = _pid(fields.pop("ProcessId", None))
    user, domain = _split_account(_text(fields.pop("User", None)))
    fields.pop("UtcTime", None)
    return FileSystemActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(user, domain, _initiating_process(image, pid)),
        file=File(path=target) if target is not None else None,
        unmapped=fields,
    )


def _map_logon(fields: dict[str, Any], ctx: _Ctx, *, success: bool) -> Authentication:
    """Map Security 4624/4625 (logon success/failure) to Authentication.

    ``LogonType`` becomes the typed ``logon_type_id``/``logon_type`` pair
    and its original value stays in ``unmapped``; ``WorkstationName`` and
    the remaining subject fields stay in ``unmapped`` too.
    """
    name = _text(fields.pop("TargetUserName", None))
    domain = _text(fields.pop("TargetDomainName", None))
    ip = _text(fields.pop("IpAddress", None))
    port = _port(fields.pop("IpPort", None))
    logon_type_id, logon_type = _logon_type_id(fields.get("LogonType"))
    fields.pop("TimeCreated", None)
    src: Endpoint | None = None
    if ip is not None or port is not None:
        src = Endpoint(ip=ip, port=port)
    return Authentication(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        status="Success" if success else "Failure",
        status_id=1 if success else 2,
        logon_type=logon_type,
        logon_type_id=logon_type_id,
        device=_device(ctx),
        actor=_actor(name, domain),
        src_endpoint=src,
        unmapped=fields,
    )


def _map_task_4698(fields: dict[str, Any], ctx: _Ctx) -> ScheduledJobActivity:
    """Map Security 4698 (scheduled task created) to Scheduled Job Activity.

    ``TaskContentNew`` (the task XML, including its command) stays in
    ``unmapped``; the subject SIDs stay there too.
    """
    task_name = _text(fields.pop("TaskName", None))
    name = _text(fields.pop("SubjectUserName", None))
    domain = _text(fields.pop("SubjectDomainName", None))
    fields.pop("TimeCreated", None)
    return ScheduledJobActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(name, domain),
        job=Job(name=task_name) if task_name is not None else None,
        unmapped=fields,
    )


def _map_task_106(fields: dict[str, Any], ctx: _Ctx) -> ScheduledJobActivity:
    """Map TaskScheduler 106 (task registered) to Scheduled Job Activity.

    ``UserData`` stays in ``unmapped`` (no typed OCSF slot).
    """
    task_name = _text(fields.pop("TaskName", None))
    name, domain = _split_account(_text(fields.pop("User", None)))
    fields.pop("TimeCreated", None)
    return ScheduledJobActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(name, domain),
        job=Job(name=task_name) if task_name is not None else None,
        unmapped=fields,
    )


_MAPPERS: dict[tuple[str, int], Callable[[dict[str, Any], _Ctx], OcsfEvent]] = {
    (SYSMON_CHANNEL, 1): _map_sysmon_process,
    (SYSMON_CHANNEL, 3): _map_sysmon_network,
    (SYSMON_CHANNEL, 11): _map_sysmon_file,
    (SECURITY_CHANNEL, 4624): lambda f, c: _map_logon(f, c, success=True),
    (SECURITY_CHANNEL, 4625): lambda f, c: _map_logon(f, c, success=False),
    (SECURITY_CHANNEL, 4698): _map_task_4698,
    (TASKSCHEDULER_CHANNEL, 106): _map_task_106,
}


def normalize_event(
    *,
    channel: str,
    event_id: int,
    fields: dict[str, Any],
    computer: str | None,
    uid: str,
    raw_time: object,
    raw_record: dict[str, Any] | None = None,
) -> OcsfEvent:
    """Normalize one record to OCSF; raise :class:`UnmappedEvent` otherwise.

    ``fields`` holds the sanitized event payload (ingestion keys already
    removed); ``raw_record`` is the sanitized record kept as ``raw_data``.
    Fields a mapper does not place stay on the event's ``unmapped`` map.
    """
    mapper = _MAPPERS.get((channel, event_id))
    if mapper is None:
        raise UnmappedEvent(channel, event_id)
    try:
        time_ms = parse_windows_time(raw_time)
    except ValueError as exc:
        raise UnmappedEvent(channel, event_id) from exc
    host = computer if isinstance(computer, str) else None
    ctx = _Ctx(uid=uid, time_ms=time_ms, channel=channel, computer=host)
    working = dict(fields)
    event = mapper(working, ctx)
    event.raw_data = json.dumps(
        raw_record if raw_record is not None else fields,
        sort_keys=True,
        default=str,
    )
    return event


def _canonical_channel(value: object) -> str:
    """Return the canonical channel spelling, case-insensitively.

    ``"security"`` becomes ``"Security"``; unknown spellings pass through
    stripped (and still count as unmapped), missing values become
    ``"unknown"``.
    """
    if isinstance(value, str) and value.strip():
        text = value.strip()
        return _CHANNEL_ALIASES.get(text.lower(), text)
    return "unknown"


def extract_evtx_parts(
    data: dict[str, Any],
) -> tuple[str, int, object, dict[str, Any], str | None, object]:
    """Split a parsed ``.evtx`` JSON record into normalizer inputs.

    Returns ``(channel, event_id, record_id, fields, computer, raw_time)``.
    Raises :class:`UnmappedEvent` ``("unknown", 0)`` when the envelope is
    not an event at all (still counted, never lost).
    """
    event = data.get("Event")
    if not isinstance(event, dict):
        raise UnmappedEvent("unknown", 0)
    system = event.get("System")
    if not isinstance(system, dict):
        raise UnmappedEvent("unknown", 0)
    channel = _canonical_channel(system.get("Channel"))
    event_id = _coerce_event_id(system.get("EventID"))
    record_id = system.get("EventRecordID")
    eventdata = event.get("EventData")
    fields = dict(eventdata) if isinstance(eventdata, dict) else {}
    created = system.get("TimeCreated")
    system_time: object = None
    if isinstance(created, dict):
        attributes = created.get("#attributes")
        if isinstance(attributes, dict):
            system_time = attributes.get("SystemTime")
    raw_time = system_time if system_time is not None else fields.get("UtcTime")
    computer = system.get("Computer")
    return (
        channel,
        event_id,
        record_id,
        fields,
        computer if isinstance(computer, str) else None,
        raw_time,
    )


def extract_flat_parts(
    record: dict[str, Any], lineno: int
) -> tuple[str, int, object, dict[str, Any], str | None, object]:
    """Split a flat OTRF JSON-lines record into normalizer inputs.

    Returns ``(channel, event_id, record_id, fields, computer, raw_time)``;
    ``record_id`` prefers ``EventIdx``/``EventRecordID`` and falls back to
    the line number so every line still gets a distinct identity.
    """
    channel = _canonical_channel(record.get("Channel"))
    event_id = _coerce_event_id(record.get("EventID"))
    record_id = record.get("EventIdx", record.get("EventRecordID", lineno))
    fields = {
        key: value for key, value in record.items() if key not in _FLAT_ENVELOPE_KEYS
    }
    computer = record.get("Computer", record.get("Hostname"))
    raw_time = record.get(
        "TimeCreated", record.get("UtcTime", record.get("@timestamp"))
    )
    return (
        channel,
        event_id,
        record_id,
        fields,
        computer if isinstance(computer, str) else None,
        raw_time,
    )


def extract_old_beat_parts(
    record: dict[str, Any], lineno: int
) -> tuple[str, int, object, dict[str, Any], str | None, object]:
    """Split an older winlogbeat record into normalizer inputs.

    That layout carries ``log_name`` / ``event_id`` / ``computer_name`` /
    ``record_number`` at the top level with the payload nested under
    ``event_data``. The payload is merged with every other top-level key
    (``message``, ``host``, ``user``, ...) so each input field ends up
    typed or in ``unmapped``; only the structurally placed envelope keys
    stay out. Returns ``(channel, event_id, record_id, fields, computer,
    raw_time)`` like :func:`extract_flat_parts`.
    """
    payload = record.get("event_data")
    merged: dict[str, Any] = dict(payload) if isinstance(payload, dict) else {}
    for key, value in record.items():
        if key in _OLD_BEAT_ENVELOPE_KEYS or key == "event_data":
            continue
        if key in INGESTION_KEYS:
            continue
        merged.setdefault(key, value)
    channel = _canonical_channel(record.get("log_name"))
    event_id = _coerce_event_id(record.get("event_id"))
    record_id = record.get("record_number", lineno)
    host = record.get("host")
    hostname = host.get("name") if isinstance(host, dict) else None
    computer = record.get("computer_name", hostname)
    event_time = merged.get("UtcTime", merged.get("TimeCreated"))
    raw_time = event_time if event_time is not None else record.get("@timestamp")
    return (
        channel,
        event_id,
        record_id,
        merged,
        computer if isinstance(computer, str) else None,
        raw_time,
    )


def extract_winlog_parts(
    record: dict[str, Any], lineno: int
) -> tuple[str, int, object, dict[str, Any], str | None, object]:
    """Split a newer nested ``winlog`` record into normalizer inputs.

    That layout nests ``channel`` / ``event_id`` / ``record_id`` /
    ``computer_name`` and the payload (``event_data``) under a top-level
    ``winlog`` object. Non-envelope keys from both levels are merged into
    the mapper payload so nothing is dropped. Returns
    ``(channel, event_id, record_id, fields, computer, raw_time)``.
    """
    winlog = record.get("winlog")
    envelope: dict[str, Any] = winlog if isinstance(winlog, dict) else {}
    payload = envelope.get("event_data")
    merged = dict(payload) if isinstance(payload, dict) else {}
    for key, value in envelope.items():
        if key in _WINLOG_ENVELOPE_KEYS:
            continue
        merged.setdefault(key, value)
    for key, value in record.items():
        if key in ("winlog", "@timestamp") or key in INGESTION_KEYS:
            continue
        merged.setdefault(key, value)
    channel = _canonical_channel(envelope.get("channel"))
    event_id = _coerce_event_id(envelope.get("event_id"))
    record_id = envelope.get("record_id", lineno)
    host = record.get("host")
    hostname = host.get("name") if isinstance(host, dict) else None
    computer = envelope.get("computer_name", hostname)
    event_time = merged.get("UtcTime", merged.get("TimeCreated"))
    raw_time = event_time if event_time is not None else record.get("@timestamp")
    return (
        channel,
        event_id,
        record_id,
        merged,
        computer if isinstance(computer, str) else None,
        raw_time,
    )


def extract_json_parts(
    record: dict[str, Any], lineno: int
) -> tuple[str, int, object, dict[str, Any], str | None, object]:
    """Split one JSON-lines record, choosing the extractor from its keys.

    Records with a ``winlog`` object use :func:`extract_winlog_parts`,
    records with a nested ``event_data`` payload plus ``log_name`` /
    ``event_id`` use :func:`extract_old_beat_parts`, and anything else
    uses :func:`extract_flat_parts`.
    """
    if isinstance(record.get("winlog"), dict):
        return extract_winlog_parts(record, lineno)
    if isinstance(record.get("event_data"), dict) and (
        "log_name" in record or "event_id" in record
    ):
        return extract_old_beat_parts(record, lineno)
    return extract_flat_parts(record, lineno)


def _normalize_parts(
    parts: tuple[str, int, object, dict[str, Any], str | None, object],
    raw_record: dict[str, Any],
    uid_base: str,
    stats: WindowsReadStats,
) -> OcsfEvent | None:
    """Normalize extracted parts, counting what misses in ``stats``."""
    channel, event_id, record_id, fields, computer, raw_time = parts
    clean_fields = sanitize_record(fields)
    clean_raw = sanitize_record(raw_record)
    try:
        return normalize_event(
            channel=channel,
            event_id=event_id,
            fields=clean_fields,
            computer=computer,
            uid=make_uid(uid_base, record_id),
            raw_time=raw_time,
            raw_record=clean_raw,
        )
    except UnmappedEvent as exc:
        stats.count(*exc.key)
        return None


def _iter_json_lines(
    stream: Iterable[bytes], uid_base: str, stats: WindowsReadStats
) -> Iterator[OcsfEvent]:
    """Yield one OCSF event per JSON line, counting what misses."""
    lineno = 0
    for raw_line in stream:
        try:
            line = raw_line.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            stats.count("unknown", 0)
            continue
        lineno += 1
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            stats.count("unknown", 0)
            continue
        if not isinstance(record, dict):
            stats.count("unknown", 0)
            continue
        try:
            parts = extract_json_parts(record, lineno)
        except (ValueError, TypeError, AttributeError):
            stats.count("unknown", 0)
            continue
        event = _normalize_parts(parts, record, uid_base, stats)
        if event is not None:
            yield event


def _iter_evtx(source: Path, rel: str, stats: WindowsReadStats) -> Iterator[OcsfEvent]:
    """Yield OCSF events from one ``.evtx`` file, counting what misses."""
    for item in PyEvtxParser(str(source)).records_json():
        if item is None:
            stats.count("unknown", 0)
            continue
        try:
            payload = item.get("data")
            data = json.loads(payload) if isinstance(payload, str) else payload
            if not isinstance(data, dict):
                raise ValueError("evtx record is not a JSON object")
            parts = extract_evtx_parts(data)
            envelope = data.get("Event")
            system: Any = (
                envelope.get("System", {}) if isinstance(envelope, dict) else {}
            )
            eventdata: Any = (
                envelope.get("EventData", {}) if isinstance(envelope, dict) else {}
            )
            raw_record = {"System": system, "EventData": eventdata}
        except UnmappedEvent as exc:
            stats.count(*exc.key)
            continue
        except (ValueError, TypeError, AttributeError, KeyError):
            stats.count("unknown", 0)
            continue
        event = _normalize_parts(parts, raw_record, rel, stats)
        if event is not None:
            yield event


def _is_archive_suffix(source: Path) -> bool:
    """Return True for ``.zip`` / ``.tar.gz`` / ``.tgz`` replay archives."""
    return source.suffix.lower() in {".zip", ".tgz"} or source.suffixes[-2:] == [
        ".tar",
        ".gz",
    ]


def iter_dataset_file(
    path: str | Path,
    *,
    dataset_rel: str | None = None,
    stats: WindowsReadStats | None = None,
) -> Iterator[OcsfEvent]:
    """Yield OCSF events from one replay file, one at a time.

    Accepts ``.evtx`` files and ``.zip`` / ``.tar.gz`` / ``.tgz`` archives of
    JSON lines; members holding no Windows event JSON (for example network
    pcaps) increment ``stats.unsupported`` instead of raising. Unmapped
    records increment ``stats.unmapped`` per ``(channel, event id)`` and
    never surface as events. Pass your own :class:`WindowsReadStats` to
    read the counts after the iterator is exhausted; the events stream so
    the caller never holds a whole dataset in memory.
    """
    source = Path(path)
    counts = stats if stats is not None else WindowsReadStats()
    rel = dataset_rel if dataset_rel is not None else source.name
    if source.suffix.lower() == ".evtx":
        yield from _iter_evtx(source, rel, counts)
    elif source.suffix.lower() == ".zip":
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if Path(info.filename).suffix.lower() != ".json":
                    counts.unsupported += 1
                    continue
                with archive.open(info) as stream:
                    yield from _iter_json_lines(
                        stream, f"{rel}#{info.filename}", counts
                    )
    elif source.suffixes[-2:] == [".tar", ".gz"] or source.suffix.lower() == ".tgz":
        with tarfile.open(source, mode="r|gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                if Path(member.name).suffix.lower() != ".json":
                    counts.unsupported += 1
                    continue
                member_stream = archive.extractfile(member)
                if member_stream is None:
                    counts.unsupported += 1
                    continue
                with member_stream:
                    yield from _iter_json_lines(
                        member_stream, f"{rel}#{member.name}", counts
                    )
    else:
        raise ValueError(f"unsupported dataset file suffix for {source}")


def _drain(path: Path, dataset_rel: str | None) -> WindowsReadResult:
    """Collect :func:`iter_dataset_file` into a :class:`WindowsReadResult`."""
    stats = WindowsReadStats()
    events = list(iter_dataset_file(path, dataset_rel=dataset_rel, stats=stats))
    return WindowsReadResult(
        events=events,
        unmapped=dict(stats.unmapped),
        unsupported=stats.unsupported,
    )


def read_evtx(path: str | Path, *, dataset_rel: str | None = None) -> WindowsReadResult:
    """Read one ``.evtx`` file into OCSF events plus unmapped counts."""
    if Path(path).suffix.lower() != ".evtx":
        raise ValueError(f"unsupported dataset file suffix for {path}")
    return _drain(Path(path), dataset_rel)


def read_otrf_archive(
    path: str | Path, *, dataset_rel: str | None = None
) -> WindowsReadResult:
    """Read one OTRF ``.zip`` / ``.tar.gz`` archive into OCSF events.

    JSON-lines members are streamed record by record; members holding no
    Windows event JSON (for example network pcaps) increment
    ``unsupported`` instead of raising.
    """
    if not _is_archive_suffix(Path(path)):
        raise ValueError(f"unsupported archive suffix for {path}")
    return _drain(Path(path), dataset_rel)


def read_dataset_file(
    path: str | Path, *, dataset_rel: str | None = None
) -> WindowsReadResult:
    """Read one replay file (``.evtx``, ``.zip``, ``.tar.gz``/``.tgz``)."""
    source = Path(path)
    if source.suffix.lower() == ".evtx":
        return read_evtx(source, dataset_rel=dataset_rel)
    if _is_archive_suffix(source):
        return read_otrf_archive(source, dataset_rel=dataset_rel)
    raise ValueError(f"unsupported dataset file suffix for {source}")
