"""Windows event normalizer: Sysmon, Security and Task Scheduler to OCSF.

Reads third-party replay formats without copying their content:
``.evtx`` files via the ``evtx`` package (pyevtx-rs ``PyEvtxParser`` with
``records_json``), bare ``.json`` JSON-lines files, and OTRF JSON-lines
members inside ``.zip`` / ``.tar.gz`` archives. :func:`iter_dataset_file`
streams one OCSF event at a time while filling a
:class:`WindowsReadStats` (archives are never loaded fully into
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
- Sysmon event 7 -> Module Activity (1005), activity Load
- Sysmon event 10 -> Process Activity (1007), activity Open
- Sysmon event 11 -> File System Activity (1001)
- Security 4624 / 4625 -> Authentication (3002), success / failure
- Security 4698 and Microsoft-Windows-TaskScheduler/Operational 106
  -> Scheduled Job Activity (1006); the first Exec command of the 4698
  task XML becomes ``job.job_actions[0].cmd_line`` (``job.cmd_line`` is
  deprecated since OCSF 1.9.0 and is never written)
- Microsoft-Windows-PowerShell/Operational 4104 and 4103, and
  Windows PowerShell 800 -> Script Activity (1009). Windows
  PowerShell 600 (provider lifecycle, no executed content) stays
  unmapped and is counted per ``(channel, event id)``.
- Sysmon event 12 -> Registry Key Activity (201001, CreateKey to
  activity 1 Create, DeleteKey to 4 Delete) and Registry Value
  Activity (201002, DeleteValue to 4 Delete, CreateValue/SetValue to
  2 Set). NXLog replaces the ``EventType`` field with the record
  severity, so the operation is read from the ``Message``
  ``EventType:`` line, falling back to Create.
- Sysmon event 13 -> Registry Value Activity (201002), activity 2 Set
- Sysmon event 14 -> Registry Key Activity (201001), activity 5 Rename
- Security 4697 and System 7045 (service installed) -> Windows
  Service Activity (201004), activity 1 Create. Mapping them to
  Scheduled Job Activity (1006) would mislabel the record, so they
  were counted unmapped until this class was added.

All times become timezone-aware UTC (naive Windows timestamps are assumed
to be UTC); a mapped event whose time cannot be parsed is counted as
unmapped under its own ``(channel, event id)``.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import xml.etree.ElementTree as ET
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
    Fingerprint,
    Job,
    JobAction,
    Metadata,
    Module,
    ModuleActivity,
    NetworkActivity,
    OcsfEvent,
    Process,
    ProcessActivity,
    Product,
    RegistryKeyActivity,
    RegistryValueActivity,
    RegKey,
    RegValue,
    ScheduledJobActivity,
    Script,
    ScriptActivity,
    User,
    WindowsServiceActivity,
    WinService,
    win_extension,
)

__all__ = [
    "POWERSHELL_CHANNEL",
    "SECURITY_CHANNEL",
    "SYSMON_CHANNEL",
    "SYSTEM_CHANNEL",
    "TASKSCHEDULER_CHANNEL",
    "WINDOWS_POWERSHELL_CHANNEL",
    "UnmappedEvent",
    "WindowsReadResult",
    "WindowsReadStats",
    "extract_evtx_parts",
    "extract_flat_parts",
    "extract_json_parts",
    "extract_old_beat_parts",
    "extract_winlog_parts",
    "wire_fields",
    "iter_dataset_file",
    "make_uid",
    "normalize_event",
    "parse_windows_time",
    "read_dataset_file",
    "read_evtx",
    "read_json_lines",
    "read_otrf_archive",
    "sanitize_record",
]

#: Real Windows channels, used verbatim as ``metadata.log_name``.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
SYSTEM_CHANNEL = "System"
TASKSCHEDULER_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
WINDOWS_POWERSHELL_CHANNEL = "Windows PowerShell"

#: Lowercased channel spellings seen in replay files -> canonical spelling.
#: Matching is case-insensitive; ``metadata.log_name`` always carries the
#: canonical spelling so downstream grouping stays deterministic. This is
#: what keeps a WEF-forwarded lowercase ``security`` record in the same
#: ``(channel, event id)`` bucket and OCSF ``log_name`` as ``Security``,
#: instead of splitting one channel into two.
_CHANNEL_ALIASES = {
    SYSMON_CHANNEL.lower(): SYSMON_CHANNEL,
    SECURITY_CHANNEL.lower(): SECURITY_CHANNEL,
    SYSTEM_CHANNEL.lower(): SYSTEM_CHANNEL,
    TASKSCHEDULER_CHANNEL.lower(): TASKSCHEDULER_CHANNEL,
    POWERSHELL_CHANNEL.lower(): POWERSHELL_CHANNEL,
    WINDOWS_POWERSHELL_CHANNEL.lower(): WINDOWS_POWERSHELL_CHANNEL,
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
    except ValueError, TypeError:
        return None
    return number if 0 <= number <= 65535 else None


def _pid(value: object) -> int | None:
    """Coerce a process id, or None when it is not a valid pid."""
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except ValueError, TypeError:
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
    except ValueError, TypeError:
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


def _metadata(ctx: _Ctx, *, with_extension: bool = False) -> Metadata:
    """Build the OCSF metadata envelope with the real Windows channel.

    Win extension classes (201001, 201002, 201004) declare the win
    extension in ``metadata.extensions`` (name ``win``, uid ``"2"``,
    version ``1.9.0`` per ``extensions/windows/extension.json`` in the
    pinned schema); core classes carry no extensions entry.
    """
    return Metadata(
        product=Product(name=_product_name(ctx.channel), vendor_name="Microsoft"),
        log_name=ctx.channel,
        uid=ctx.uid,
        extensions=[win_extension()] if with_extension else None,
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


def _take_text(fields: dict[str, Any], key: str) -> str | None:
    """Pop ``key`` and return its text, restoring placeholders to ``unmapped``.

    Like :func:`_text`, but a present-but-placeholder value is put back
    instead of dropped, so evidence fields (registry paths, service
    names) never vanish: every input field still ends up typed or in
    ``unmapped``. A missing key (or an explicit null) stays missing.
    """
    if key not in fields:
        return None
    raw = fields.pop(key)
    text = _text(raw)
    if text is None and raw is not None:
        fields[key] = raw
    return text


#: Windows LogonType -> OCSF ``logon_type_id``. Windows 0 (System) is OCSF 1;
#: 12 and 13 pass straight through to the same OCSF ids; anything else
#: without an OCSF counterpart maps to OCSF 99 (Other).
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
    12: 12,
    13: 13,
}

#: Captions of the pinned OCSF 1.9.0 ``logon_type_id`` enum (``dictionary.json``
#: ``attributes.logon_type_id.enum`` in ``ocsf-schema`` tag ``1.9.0``).
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
    except ValueError, TypeError:
        return None, None
    mapped = _WINDOWS_TO_OCSF_LOGON_TYPE.get(number, 99)
    return mapped, _LOGON_TYPE_CAPTIONS[mapped]


#: Captions of the pinned OCSF 1.9.0 win ``service_start_type_id`` enum
#: (``extensions/windows/dictionary.json``
#: ``attributes.service_start_type_id.enum`` in ``ocsf-schema`` tag
#: ``1.9.0``).
_START_TYPE_CAPTIONS = {
    0: "Unknown",
    1: "Boot",
    2: "System",
    3: "Auto",
    4: "Demand",
    5: "Disabled",
    99: "Other",
}

#: Service Control Manager numeric start type -> OCSF
#: ``service_start_type_id`` (Security 4697 ``ServiceStartType``). SCM
#: numbers boot 0 through disabled 4, one below the OCSF ids.
_SCM_START_TYPE_TO_OCSF = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5}

#: System 7045 ``StartType`` words (lowercased) -> OCSF id.
_START_TYPE_WORDS = {
    "boot start": 1,
    "system start": 2,
    "auto start": 3,
    "demand start": 4,
    "disabled": 5,
}

#: Captions of the pinned OCSF 1.9.0 win ``service_type_id`` enum
#: (``extensions/windows/dictionary.json``
#: ``attributes.service_type_id.enum``).
_SERVICE_TYPE_CAPTIONS = {
    0: "Unknown",
    1: "Kernel Driver",
    2: "File System Driver",
    3: "Own Process",
    4: "Share Process",
    99: "Other",
}

#: SCM numeric service type -> OCSF ``service_type_id`` (Security 4697
#: ``ServiceType``, a hex bitmask: 0x1 kernel, 0x2 file system driver,
#: 0x10 own process, 0x20 share process).
_SCM_SERVICE_TYPE_TO_OCSF = {1: 1, 2: 2, 16: 3, 32: 4}

#: System 7045 ``ServiceType`` words (lowercased) -> OCSF id. A
#: user-mode service owns or shares a process indistinguishably here,
#: so it maps to 99 Other with the raw words kept.
_SERVICE_TYPE_WORDS = {"kernel mode driver": 1, "file system driver": 2}


def _service_start_type(value: object) -> tuple[int | None, str | None]:
    """Map a service start type to ``(service_start_type_id, service_start_type)``.

    Accepts SCM numbers (Security 4697 ``ServiceStartType``) and System
    7045 words (``"auto start"``). Unknown values become 99 Other with
    the raw string, per the sibling convention (Other carries the
    event-source value); unusable values become ``(None, None)``. The
    caller reads the raw with ``.get`` so it stays in ``unmapped``.
    """
    if isinstance(value, bool) or value is None:
        return None, None
    text = str(value).strip()
    if not text or text.lower() in PLACEHOLDERS:
        return None, None
    try:
        number: int | None = int(text, 0)
    except ValueError, TypeError:
        number = None
    if number is not None:
        mapped = _SCM_START_TYPE_TO_OCSF.get(number)
        if mapped is not None:
            return mapped, _START_TYPE_CAPTIONS[mapped]
        return 99, text
    mapped = _START_TYPE_WORDS.get(text.lower())
    if mapped is not None:
        return mapped, _START_TYPE_CAPTIONS[mapped]
    return 99, text


def _service_type(value: object) -> tuple[int | None, str | None]:
    """Map a service type to ``(service_type_id, service_type)``.

    Same contract as :func:`_service_start_type`: SCM numbers or hex
    (Security 4697 ``ServiceType``) and System 7045 words, unknown to
    99 Other with the raw string, unusable to ``(None, None)``.
    """
    if isinstance(value, bool) or value is None:
        return None, None
    text = str(value).strip()
    if not text or text.lower() in PLACEHOLDERS:
        return None, None
    try:
        number: int | None = int(text, 0)
    except ValueError, TypeError:
        number = None
    if number is not None:
        mapped = _SCM_SERVICE_TYPE_TO_OCSF.get(number)
        if mapped is not None:
            return mapped, _SERVICE_TYPE_CAPTIONS[mapped]
        return 99, text
    mapped = _SERVICE_TYPE_WORDS.get(text.lower())
    if mapped is not None:
        return mapped, _SERVICE_TYPE_CAPTIONS[mapped]
    return 99, text


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


#: Sysmon ``Hashes`` algorithm name (uppercased) -> OCSF
#: ``algorithm_id`` from ``objects/fingerprint.json``
#: ``attributes.algorithm_id.enum`` in ``ocsf-schema`` tag ``1.9.0``.
_HASH_ALGORITHM_IDS = {"MD5": 1, "SHA1": 2, "SHA256": 3, "IMPHASH": 18}

#: OCSF ``algorithm_id`` -> enum caption (``algorithm`` carries the
#: caption for known ids).
_HASH_ALGORITHM_CAPTIONS = {
    1: "MD5",
    2: "SHA-1",
    3: "SHA-256",
    18: "Imphash",
    99: "Other",
}


def _parse_hashes(raw: object) -> list[Fingerprint] | None:
    """Split a Sysmon ``Hashes`` value into fingerprint objects.

    The value is comma-separated ``ALG=hex`` pairs (Sysmon 7 carries
    ``SHA1``/``MD5``/``SHA256``/``IMPHASH``). Known names map to the
    pinned OCSF 1.9.0 ``algorithm_id`` enum with the enum caption in
    ``algorithm``; anything else becomes 99 Other with the source name
    kept verbatim in ``algorithm``. Returns None when nothing usable
    remains; the caller then keeps the raw value in ``unmapped``.
    """
    text = _text(raw)
    if text is None:
        return None
    pairs = []
    for chunk in text.split(","):
        name, sep, digest = chunk.partition("=")
        name = name.strip()
        digest = digest.strip()
        if not (sep and name and digest):
            continue
        algorithm_id = _HASH_ALGORITHM_IDS.get(name.upper(), 99)
        if algorithm_id == 99:
            algorithm = name
        else:
            algorithm = _HASH_ALGORITHM_CAPTIONS[algorithm_id]
        pairs.append(
            Fingerprint(algorithm=algorithm, algorithm_id=algorithm_id, value=digest)
        )
    return pairs or None


def _map_sysmon_module(fields: dict[str, Any], ctx: _Ctx) -> ModuleActivity:
    """Map Sysmon event 7 (image loaded) to Module Activity.

    Class 1005, activity 1 Load per the pinned OCSF 1.9.0 schema
    (``events/system/module_activity.json``: uid 5 under the system
    category). ``ImageLoaded`` becomes ``module.file`` (the name derived
    as for other files); the loading process (``Image``/``ProcessId``)
    becomes ``actor.process``; the user follows the other Sysmon
    mappers (``User``, else the NXLog ``AccountName``/``Domain`` pair).
    Typed file slots follow ``objects/file.json``: ``Hashes`` to
    ``hashes``, ``Description`` to ``desc``, ``Company`` to
    ``company_name``, ``Product`` to ``product.name``, and
    ``OriginalFileName`` to ``internal_name`` (the VERSIONINFO name).
    ``Signed``/``Signature``/``SignatureStatus`` have no typed slot —
    ``file.signature`` is deprecated since 1.8.0 — so they stay verbatim
    in ``unmapped``, as do ``FileVersion``, ``ProcessGuid``,
    ``RuleName``, ``EventType`` and the rest.
    """
    loaded = _take_text(fields, "ImageLoaded")
    image = _text(fields.pop("Image", None))
    pid = _pid(fields.pop("ProcessId", None))
    raw_user = _text(fields.pop("User", None))
    if raw_user is not None:
        user, domain = _split_account(raw_user)
    else:
        user = _take_text(fields, "AccountName")
        domain = _take_text(fields, "Domain")
    raw_hashes = fields.pop("Hashes", None)
    hashes = _parse_hashes(raw_hashes)
    if hashes is None and raw_hashes is not None:
        fields["Hashes"] = raw_hashes
    desc = _take_text(fields, "Description")
    company = _take_text(fields, "Company")
    product_name = _take_text(fields, "Product")
    internal = _take_text(fields, "OriginalFileName")
    fields.pop("UtcTime", None)
    file: File | None = None
    if (
        loaded is not None
        or hashes is not None
        or desc is not None
        or company is not None
        or product_name is not None
        or internal is not None
    ):
        file = File(
            path=loaded,
            hashes=hashes,
            desc=desc,
            company_name=company,
            product=Product(name=product_name) if product_name is not None else None,
            internal_name=internal,
        )
    return ModuleActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(user, domain, _initiating_process(image, pid)),
        module=Module(file=file) if file is not None else None,
        unmapped=fields,
    )


def _map_sysmon_access(fields: dict[str, Any], ctx: _Ctx) -> ProcessActivity:
    """Map Sysmon event 10 (process handle open) to Process Activity.

    Activity 3 Open per the pinned OCSF 1.9.0 schema
    (``events/system/process_activity.json`` activity enum). The opening
    process (``SourceImage``/``SourceProcessId``) becomes ``actor.process``
    and the target (``TargetImage``/``TargetProcessId``) becomes
    ``process``. ``GrantedAccess`` is kept verbatim as the typed
    ``actual_permissions`` (the schema's platform-native slot, per that
    same file). ``CallTrace`` has no typed OCSF 1.9.0 slot — the full
    ``process`` object attribute list in ``objects/process.json`` carries
    nothing like it — so it stays in ``unmapped``, as do the GUIDs and
    the source thread id.
    """
    source_image = _text(fields.pop("SourceImage", None))
    source_pid = _pid(fields.pop("SourceProcessId", None))
    target_image = _text(fields.pop("TargetImage", None))
    target_pid = _pid(fields.pop("TargetProcessId", None))
    granted = _text(fields.pop("GrantedAccess", None))
    user, domain = _split_account(_text(fields.pop("User", None)))
    fields.pop("UtcTime", None)
    source: Process | None = None
    if source_pid is not None or source_image is not None:
        source = Process(
            pid=source_pid,
            name=_basename(source_image),
            file=File(path=source_image) if source_image is not None else None,
        )
    target: Process | None = None
    if target_pid is not None or target_image is not None:
        target = Process(
            pid=target_pid,
            name=_basename(target_image),
            file=File(path=target_image) if target_image is not None else None,
        )
    return ProcessActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=3,
        device=_device(ctx),
        actor=_actor(user, domain, source),
        process=target,
        actual_permissions=granted,
        unmapped=fields,
    )


def _script_actor(fields: dict[str, Any]) -> Actor | None:
    """Actor for a script record: ``User``, else ``AccountName``/``Domain``.

    Flat NXLog records (the APT29 compound layout) carry the account as
    separate ``AccountName`` and ``Domain`` fields instead of one ``User``
    ``DOMAIN\\name`` string.
    """
    raw_user = _text(fields.pop("User", None))
    if raw_user is not None:
        name, domain = _split_account(raw_user)
        return _actor(name, domain)
    name = _text(fields.pop("AccountName", None))
    domain = _text(fields.pop("Domain", None))
    return _actor(name, domain)


def _script_event(
    fields: dict[str, Any], ctx: _Ctx, content: str | None, block_id: str | None
) -> ScriptActivity:
    """Build one Script Activity (1009, Execute) from script content."""
    fields.pop("TimeCreated", None)
    script: Script | None = None
    if content is not None or block_id is not None:
        script = Script(
            uid=block_id,
            script_content=content,
            type="PowerShell",
            type_id=2,
        )
    return ScriptActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_script_actor(fields),
        script=script,
        unmapped=fields,
    )


def _map_powershell_script(fields: dict[str, Any], ctx: _Ctx) -> ScriptActivity:
    """Map PowerShell Operational 4104 (script block logging).

    Class 1009, activity 1 Execute per the pinned OCSF 1.9.0 schema
    (``events/system/script_activity.json``: uid 9 under the system
    category). The typed script fields follow ``objects/script.json``,
    where ``uid`` is documented as the PowerShell ``ScriptBlockId``.
    ``MessageNumber``/``MessageTotal`` have no typed slot and stay in
    ``unmapped``. Each record maps to its own event; the messages of a
    split block share the script ``uid`` for downstream grouping.
    """
    content = _text(fields.pop("ScriptBlockText", None))
    block_id = _text(fields.pop("ScriptBlockId", None))
    return _script_event(fields, ctx, content, block_id)


def _map_powershell_module(fields: dict[str, Any], ctx: _Ctx) -> ScriptActivity:
    """Map PowerShell Operational 4103 (module logging) to Script Activity.

    Same class/activity as 4104. The executed command invocation is in
    ``Payload`` (there is no ``ScriptBlockId``, so ``script.uid`` stays
    empty); ``ContextInfo`` has no typed slot and stays in ``unmapped``.
    """
    content = _text(fields.pop("Payload", None))
    return _script_event(fields, ctx, content, None)


def _map_windows_powershell_pipeline(
    fields: dict[str, Any], ctx: _Ctx
) -> ScriptActivity:
    """Map Windows PowerShell 800 (pipeline execution) to Script Activity.

    Same class/activity as 4104. This classic channel carries the
    pipeline detail only in ``Message``, which becomes the script
    content; there is no block id. Event 600 (provider lifecycle)
    carries no executed content and stays unmapped.
    """
    content = _text(fields.pop("Message", None))
    return _script_event(fields, ctx, content, None)


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


#: Line-anchored Sysmon operation inside an NXLog-rendered ``Message``.
_MESSAGE_EVENT_TYPE = re.compile(r"^EventType:\s*(\w+)", re.MULTILINE)

#: Operations a Sysmon registry record may carry, in the ``EventType``
#: field or on the ``Message`` ``EventType:`` line.
_REGISTRY_OPS = frozenset(
    {
        "CreateKey",
        "DeleteKey",
        "CreateValue",
        "DeleteValue",
        "SetValue",
        "RenameKey",
    }
)


def _registry_op(fields: dict[str, Any]) -> str | None:
    """Return the Sysmon registry operation, or None when unknown.

    NXLog replaces the ``EventType`` field with the record severity
    (``INFO`` on every flat day-1 Sysmon 12/13 record); the real
    operation then lives only on the ``Message`` ``EventType: <op>``
    line. Prefer a known ``EventType`` value, else the ``Message``
    line. Both stay in ``unmapped``: this reads without popping.
    """
    event_type = _text(fields.get("EventType"))
    if event_type in _REGISTRY_OPS:
        return event_type
    message = fields.get("Message")
    if isinstance(message, str):
        found = _MESSAGE_EVENT_TYPE.search(message)
        if found is not None and found.group(1) in _REGISTRY_OPS:
            return found.group(1)
    return None


def _registry_actor(
    fields: dict[str, Any], image: str | None, pid: int | None
) -> Actor | None:
    """Build the actor for a Sysmon registry record.

    Registry events carry no ``User`` key (unlike Sysmon 1/3/10/11);
    the NXLog ``AccountName``/``Domain`` pair names the writer
    (``SYSTEM`` / ``NT AUTHORITY`` on every day-1 record). ``UserID``
    (a SID) has no typed OCSF slot and stays in ``unmapped``.
    """
    name = _take_text(fields, "AccountName")
    domain = _take_text(fields, "Domain")
    return _actor(name, domain, _initiating_process(image, pid))


def _registry_value(target: str | None, data: str | None = None) -> RegValue | None:
    """Build a ``reg_value`` with the name derived from the path.

    The value name is the last backslash component of ``TargetObject``
    (mirroring the ``File.name`` derivation); the path stays verbatim.
    """
    if target is not None:
        return RegValue(
            name=target.replace("/", "\\").rsplit("\\", 1)[-1] or None,
            path=target,
            data=data,
        )
    if data is not None:
        return RegValue(data=data)
    return None


def _map_sysmon_registry_key(
    fields: dict[str, Any], ctx: _Ctx
) -> RegistryKeyActivity | RegistryValueActivity:
    """Map Sysmon event 12 (registry object added or deleted).

    Classes 201001/201002 per the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/registry_key_activity.json``: uid 1,
    and ``registry_value_activity.json``: uid 2, both ``extends``
    system). The operation comes from the ``EventType`` field or, when
    NXLog replaced it with the severity, from the ``Message``
    ``EventType:`` line (see :func:`_registry_op`); both stay in
    ``unmapped``. ``CreateKey`` -> Key 1 Create, ``DeleteKey`` -> Key
    4 Delete, ``DeleteValue`` -> Value 4 Delete (a value delete is a
    value record, per ``registry_value_activity.json``),
    ``CreateValue``/``SetValue`` -> Value 2 Set, ``RenameKey`` -> Key
    5 Rename, and anything unknown -> Key 1 Create. ``TargetObject``
    becomes ``reg_key.path`` / ``reg_value.path`` verbatim. The
    initiating process (``Image``/``ProcessId``) becomes
    ``actor.process``; ``ProcessGuid``, ``RuleName``, ``EventType``,
    ``Message`` and the rest stay in ``unmapped``.
    """
    op = _registry_op(fields)
    target = _take_text(fields, "TargetObject")
    image = _take_text(fields, "Image")
    pid = _pid(fields.pop("ProcessId", None))
    fields.pop("UtcTime", None)
    actor = _registry_actor(fields, image, pid)
    device = _device(ctx)
    if op == "DeleteValue":
        return RegistryValueActivity(
            time=ctx.time_ms,
            metadata=_metadata(ctx, with_extension=True),
            activity_id=4,
            device=device,
            actor=actor,
            reg_value=_registry_value(target),
            unmapped=fields,
        )
    if op in ("CreateValue", "SetValue"):
        return RegistryValueActivity(
            time=ctx.time_ms,
            metadata=_metadata(ctx, with_extension=True),
            activity_id=2,
            device=device,
            actor=actor,
            reg_value=_registry_value(target),
            unmapped=fields,
        )
    if op == "RenameKey":
        return RegistryKeyActivity(
            time=ctx.time_ms,
            metadata=_metadata(ctx, with_extension=True),
            activity_id=5,
            device=device,
            actor=actor,
            reg_key=RegKey(path=target) if target is not None else None,
            unmapped=fields,
        )
    return RegistryKeyActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx, with_extension=True),
        activity_id=4 if op == "DeleteKey" else 1,
        device=device,
        actor=actor,
        reg_key=RegKey(path=target) if target is not None else None,
        unmapped=fields,
    )


def _map_sysmon_registry_value(
    fields: dict[str, Any], ctx: _Ctx
) -> RegistryValueActivity:
    """Map Sysmon event 13 (registry value set) to Registry Value Activity.

    Class 201002 per the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/registry_value_activity.json``: uid 2,
    ``extends`` system). Event 13 sets one value, so the activity is 2
    Set from that file's enum; ``EventType`` (``SetValue``, or the
    NXLog ``INFO`` filler) stays in ``unmapped``. ``TargetObject``
    becomes ``reg_value.path`` verbatim with the value name derived as
    its last backslash component (mirroring the ``File.name``
    derivation); ``Details`` becomes ``reg_value.data`` verbatim.
    """
    target = _take_text(fields, "TargetObject")
    data = _take_text(fields, "Details")
    image = _take_text(fields, "Image")
    pid = _pid(fields.pop("ProcessId", None))
    fields.pop("UtcTime", None)
    value = _registry_value(target, data)
    return RegistryValueActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx, with_extension=True),
        activity_id=2,
        device=_device(ctx),
        actor=_registry_actor(fields, image, pid),
        reg_value=value,
        unmapped=fields,
    )


def _map_sysmon_registry_rename(
    fields: dict[str, Any], ctx: _Ctx
) -> RegistryKeyActivity:
    """Map Sysmon event 14 (registry object renamed) to Registry Key Activity.

    Class 201001 per the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/registry_key_activity.json``), activity
    5 Rename from that file's enum, so no ``EventType`` is needed:
    ``NewName`` is the post-rename path (``reg_key``) and
    ``TargetObject`` the pre-rename path (``prev_reg_key``, "the
    registry key before the mutation" in that file); without
    ``NewName`` the target is the key. Any ``EventType`` or NXLog
    ``EventTypeOrignal`` filler stays in ``unmapped``.
    """
    target = _take_text(fields, "TargetObject")
    new_name = _take_text(fields, "NewName")
    image = _take_text(fields, "Image")
    pid = _pid(fields.pop("ProcessId", None))
    fields.pop("UtcTime", None)
    key = new_name if new_name is not None else target
    prev = target if new_name is not None and target != new_name else None
    return RegistryKeyActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx, with_extension=True),
        activity_id=5,
        device=_device(ctx),
        actor=_registry_actor(fields, image, pid),
        reg_key=RegKey(path=key) if key is not None else None,
        prev_reg_key=RegKey(path=prev) if prev is not None else None,
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


def _task_command(task_xml: str | None) -> str | None:
    """Extract the first Exec command from a scheduled-task XML blob.

    Security 4698 ``TaskContentNew`` carries the task definition XML
    (namespaced ``http://schemas.microsoft.com/windows/2004/02/mit/task``
    on real records, bare tags in some fixtures). The executed command
    is the first ``Actions`` / ``Exec`` ``Command`` with its optional
    ``Arguments`` appended. Tags match by local name so either spelling
    parses; the raw XML always stays in ``unmapped`` (no typed OCSF slot
    for it). Returns None when the XML does not parse or names no
    executable command.
    """
    if task_xml is None:
        return None
    try:
        root = ET.fromstring(task_xml)
    except ET.ParseError:
        return None
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] != "Exec":
            continue
        command: str | None = None
        arguments: str | None = None
        for child in elem:
            local = child.tag.rsplit("}", 1)[-1]
            if local == "Command" and command is None:
                command = (child.text or "").strip() or None
            elif local == "Arguments" and arguments is None:
                arguments = (child.text or "").strip() or None
        if command is None:
            return None
        return f"{command} {arguments}" if arguments else command
    return None


def _map_task_4698(fields: dict[str, Any], ctx: _Ctx) -> ScheduledJobActivity:
    """Map Security 4698 (scheduled task created) to Scheduled Job Activity.

    The first Exec command of the ``TaskContentNew`` XML becomes
    ``job.job_actions[0]`` with ``cmd_line`` plus ``type_id`` 2
    (``type`` ``"Execute"`` from the pinned OCSF 1.9.0
    ``job_action`` enum; ``job.cmd_line`` is deprecated since 1.9.0).
    The raw XML stays in ``unmapped``, as do the subject SIDs. Records
    whose XML does not parse still map, with no actions.
    """
    task_name = _text(fields.pop("TaskName", None))
    name = _text(fields.pop("SubjectUserName", None))
    domain = _text(fields.pop("SubjectDomainName", None))
    command = _task_command(_text(fields.get("TaskContentNew")))
    fields.pop("TimeCreated", None)
    job: Job | None = None
    if task_name is not None or command is not None:
        job = Job(
            name=task_name,
            job_actions=(
                [JobAction(cmd_line=command, type="Execute", type_id=2)]
                if command is not None
                else None
            ),
        )
    return ScheduledJobActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx),
        activity_id=1,
        device=_device(ctx),
        actor=_actor(name, domain),
        job=job,
        unmapped=fields,
    )


def _map_task_106(fields: dict[str, Any], ctx: _Ctx) -> ScheduledJobActivity:
    """Map TaskScheduler 106 (task registered) to Scheduled Job Activity.

    This layout names no executable command, so the job carries the
    name only (``job_actions`` stays empty; ``job.cmd_line`` is
    deprecated since OCSF 1.9.0 and is never written). ``UserData``
    stays in ``unmapped`` (no typed OCSF slot).
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


def _service_event(
    fields: dict[str, Any], ctx: _Ctx, service: WinService | None, actor: Actor | None
) -> WindowsServiceActivity:
    """Build one Windows Service Activity (201004, Create) event."""
    fields.pop("TimeCreated", None)
    return WindowsServiceActivity(
        time=ctx.time_ms,
        metadata=_metadata(ctx, with_extension=True),
        activity_id=1,
        device=_device(ctx),
        actor=actor,
        win_service=service,
        unmapped=fields,
    )


def _map_service_4697(fields: dict[str, Any], ctx: _Ctx) -> WindowsServiceActivity:
    """Map Security 4697 (a service was installed) to Service Activity.

    Class 201004 per the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/windows_service_activity.json``: uid 4,
    ``extends`` system), activity 1 Create from that file's enum.
    ``ServiceName`` becomes ``win_service.name``,
    ``ServiceFileName`` becomes ``cmd_line``,
    ``ServiceStartType`` (an SCM number) and ``ServiceType`` (a hex
    bitmask) become the typed id/caption pairs, and
    ``ServiceAccount`` becomes ``service_start_name``; the raw type
    values stay in ``unmapped``. ``SubjectUserName`` /
    ``SubjectDomainName`` name the installer and become the actor.
    """
    name = _take_text(fields, "ServiceName")
    cmd_line = _take_text(fields, "ServiceFileName")
    start_type_id, start_type = _service_start_type(fields.get("ServiceStartType"))
    type_id, service_type = _service_type(fields.get("ServiceType"))
    start_name = _take_text(fields, "ServiceAccount")
    actor_name = _take_text(fields, "SubjectUserName")
    actor_domain = _take_text(fields, "SubjectDomainName")
    service: WinService | None = None
    if (
        name is not None
        or cmd_line is not None
        or start_name is not None
        or start_type_id is not None
        or type_id is not None
    ):
        service = WinService(
            name=name,
            cmd_line=cmd_line,
            service_start_name=start_name,
            service_start_type=start_type,
            service_start_type_id=start_type_id,
            service_type=service_type,
            service_type_id=type_id,
        )
    return _service_event(fields, ctx, service, _actor(actor_name, actor_domain))


def _map_service_7045(fields: dict[str, Any], ctx: _Ctx) -> WindowsServiceActivity:
    """Map System 7045 (a service was installed) to Service Activity.

    Same class and activity as Security 4697. ``ServiceName`` becomes
    ``win_service.name`` and ``ImagePath`` becomes ``cmd_line``;
    ``StartType`` words (``"auto start"``) and ``ServiceType`` words
    (``"user mode service"``) become the typed id/caption pairs. This
    layout carries no service-account field, so ``service_start_name``
    stays empty; ``AccountName`` / ``Domain`` name the installing
    subject (the same account as the matching 4697 installer) and
    become the actor, while ``UserID`` stays in ``unmapped``.
    """
    name = _take_text(fields, "ServiceName")
    cmd_line = _take_text(fields, "ImagePath")
    start_type_id, start_type = _service_start_type(fields.get("StartType"))
    type_id, service_type = _service_type(fields.get("ServiceType"))
    actor_name = _take_text(fields, "AccountName")
    actor_domain = _take_text(fields, "Domain")
    service: WinService | None = None
    if (
        name is not None
        or cmd_line is not None
        or start_type_id is not None
        or type_id is not None
    ):
        service = WinService(
            name=name,
            cmd_line=cmd_line,
            service_start_type=start_type,
            service_start_type_id=start_type_id,
            service_type=service_type,
            service_type_id=type_id,
        )
    return _service_event(fields, ctx, service, _actor(actor_name, actor_domain))


_MAPPERS: dict[tuple[str, int], Callable[[dict[str, Any], _Ctx], OcsfEvent]] = {
    (SYSMON_CHANNEL, 1): _map_sysmon_process,
    (SYSMON_CHANNEL, 3): _map_sysmon_network,
    (SYSMON_CHANNEL, 7): _map_sysmon_module,
    (SYSMON_CHANNEL, 10): _map_sysmon_access,
    (SYSMON_CHANNEL, 11): _map_sysmon_file,
    (SYSMON_CHANNEL, 12): _map_sysmon_registry_key,
    (SYSMON_CHANNEL, 13): _map_sysmon_registry_value,
    (SYSMON_CHANNEL, 14): _map_sysmon_registry_rename,
    (SECURITY_CHANNEL, 4624): lambda f, c: _map_logon(f, c, success=True),
    (SECURITY_CHANNEL, 4625): lambda f, c: _map_logon(f, c, success=False),
    (SECURITY_CHANNEL, 4697): _map_service_4697,
    (SECURITY_CHANNEL, 4698): _map_task_4698,
    (SYSTEM_CHANNEL, 7045): _map_service_7045,
    (TASKSCHEDULER_CHANNEL, 106): _map_task_106,
    (POWERSHELL_CHANNEL, 4104): _map_powershell_script,
    (POWERSHELL_CHANNEL, 4103): _map_powershell_module,
    (WINDOWS_POWERSHELL_CHANNEL, 800): _map_windows_powershell_pipeline,
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


def _provider_name(system: dict[str, Any]) -> str | None:
    """Return the ``System.Provider`` name, or None when it is missing."""
    provider = system.get("Provider")
    if isinstance(provider, str):
        return provider.strip() or None
    if isinstance(provider, dict):
        attributes = provider.get("#attributes")
        if isinstance(attributes, dict):
            name = attributes.get("Name")
            if isinstance(name, str) and name.strip():
                return name.strip()
    return None


def extract_evtx_parts(
    data: dict[str, Any],
) -> tuple[str, int, object, dict[str, Any], str | None, object]:
    """Split a parsed ``.evtx`` JSON record into normalizer inputs.

    Returns ``(channel, event_id, record_id, fields, computer, raw_time)``.
    Records with no channel (ETW traces converted to ``.evtx``) count under
    the ``System.Provider`` name instead of ``"unknown"``. Raises
    :class:`UnmappedEvent` ``("unknown", 0)`` when the envelope is
    not an event at all (still counted, never lost).
    """
    event = data.get("Event")
    if not isinstance(event, dict):
        raise UnmappedEvent("unknown", 0)
    system = event.get("System")
    if not isinstance(system, dict):
        raise UnmappedEvent("unknown", 0)
    raw_channel = system.get("Channel")
    if not (isinstance(raw_channel, str) and raw_channel.strip()):
        raw_channel = _provider_name(system)
    channel = _canonical_channel(raw_channel)
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


def wire_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the pre-mapper payload for one raw record.

    Reuses the layout dispatch the normalizer itself uses
    (:func:`extract_evtx_parts` for the EVTX ``Event`` / ``System`` /
    ``EventData`` envelope — the store keeps the trimmed
    ``{"System", "EventData"}`` form, which rewraps exactly — and
    :func:`extract_json_parts` for the flat, old-beat and winlog JSON
    layouts), so the detector's raw fallback reads precisely the value
    the mapper saw under each wire name. Returns an empty mapping
    when the record is not a mappable event in any layout.
    """
    candidate = record
    system = record.get("System")
    eventdata = record.get("EventData")
    if isinstance(system, dict) and isinstance(eventdata, dict):
        candidate = {"Event": record}
    try:
        if isinstance(candidate.get("Event"), dict):
            _, _, _, fields, _, _ = extract_evtx_parts(candidate)
        else:
            _, _, _, fields, _, _ = extract_json_parts(candidate, 0)
    except UnmappedEvent, ValueError, TypeError, AttributeError, KeyError:
        return {}
    return dict(fields) if isinstance(fields, dict) else {}


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
        except UnicodeDecodeError, AttributeError:
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
        except ValueError, TypeError, AttributeError:
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
        except ValueError, TypeError, AttributeError, KeyError:
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

    Accepts ``.evtx`` files, bare ``.json`` JSON-lines files, and ``.zip`` /
    ``.tar.gz`` / ``.tgz`` archives of JSON lines; archive members holding
    no Windows event JSON (for example network pcaps) increment
    ``stats.unsupported`` instead of raising. Unmapped records increment
    ``stats.unmapped`` per ``(channel, event id)`` and never surface as
    events. Pass your own :class:`WindowsReadStats` to read the counts
    after the iterator is exhausted; the events stream so the caller never
    holds a whole dataset in memory.
    """
    source = Path(path)
    counts = stats if stats is not None else WindowsReadStats()
    rel = dataset_rel if dataset_rel is not None else source.name
    if source.suffix.lower() == ".evtx":
        yield from _iter_evtx(source, rel, counts)
    elif source.suffix.lower() == ".json":
        with open(source, "rb") as stream:
            yield from _iter_json_lines(stream, rel, counts)
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


def read_json_lines(
    path: str | Path, *, dataset_rel: str | None = None
) -> WindowsReadResult:
    """Read one bare ``.json`` JSON-lines file into OCSF events."""
    if Path(path).suffix.lower() != ".json":
        raise ValueError(f"unsupported dataset file suffix for {path}")
    return _drain(Path(path), dataset_rel)


def read_dataset_file(
    path: str | Path, *, dataset_rel: str | None = None
) -> WindowsReadResult:
    """Read one replay file (``.evtx``, ``.json``, ``.zip``, ``.tar.gz``/``.tgz``)."""
    source = Path(path)
    if source.suffix.lower() == ".evtx":
        return read_evtx(source, dataset_rel=dataset_rel)
    if source.suffix.lower() == ".json":
        return read_json_lines(source, dataset_rel=dataset_rel)
    if _is_archive_suffix(source):
        return read_otrf_archive(source, dataset_rel=dataset_rel)
    raise ValueError(f"unsupported dataset file suffix for {source}")
