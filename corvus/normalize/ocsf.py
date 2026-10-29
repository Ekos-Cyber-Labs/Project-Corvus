"""Pinned OCSF event models for Corvus normalization.

Everything inside Corvus is OCSF at the version pinned by
``OCSF_SCHEMA_VERSION``. Field names and activity IDs match the OCSF 1.9.0
schema (schema.ocsf.io, ``ocsf-schema`` tag ``1.9.0``): ``actor.user``,
``metadata.product`` and ``metadata.log_name``, ``process.file``. These
models carry only the fields deterministic correlation needs, plus
``raw_data`` (the original event as a JSON string) and ``unmapped``
(anything a mapper could not place, counted, never dropped silently).
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

OCSF_SCHEMA_VERSION = "1.9.0"

#: The Windows schema extension, from ``extensions/windows/extension.json``
#: in ``ocsf-schema`` tag ``1.9.0`` (uid ``"2"``, name ``win``). Every event
#: of a win extension class (201001, 201002, 201004) carries one
#: :class:`Extension` with these values in ``metadata.extensions``; events
#: of core classes carry no extensions entry.
WIN_EXTENSION_NAME = "win"
WIN_EXTENSION_UID = "2"
WIN_EXTENSION_VERSION = "1.9.0"

#: Earliest accepted event time (2000-01-01T00:00:00Z) as UTC epoch ms.
#: Anything below it is almost certainly epoch seconds, not milliseconds.
MIN_TIME_MS = 946684800000

#: Spellings that mean "no value" (compared case-insensitively).
PLACEHOLDERS = frozenset({"", "-", "n/a", "unknown"})

__all__ = [
    "MIN_TIME_MS",
    "OCSF_SCHEMA_VERSION",
    "PLACEHOLDERS",
    "Actor",
    "Analytic",
    "AttackRef",
    "Authentication",
    "DetectionFinding",
    "FindingInfo",
    "Device",
    "Endpoint",
    "EntityKeys",
    "Evidence",
    "Extension",
    "File",
    "Fingerprint",
    "FileSystemActivity",
    "Job",
    "JobAction",
    "Metadata",
    "Module",
    "ModuleActivity",
    "NetworkActivity",
    "OcsfEvent",
    "OcsfEventBase",
    "Process",
    "ProcessActivity",
    "Product",
    "RegKey",
    "RelatedEvent",
    "TacticRef",
    "TechniqueRef",
    "RegValue",
    "RegistryKeyActivity",
    "RegistryValueActivity",
    "ScheduledJobActivity",
    "Script",
    "ScriptActivity",
    "ScriptContent",
    "User",
    "WIN_EXTENSION_NAME",
    "WIN_EXTENSION_UID",
    "WIN_EXTENSION_VERSION",
    "WinService",
    "WindowsServiceActivity",
    "win_extension",
    "canonicalize_host",
    "canonicalize_ip",
    "canonicalize_user",
    "compute_entity_keys",
]


def _clean(value: str | None) -> str:
    """Strip a raw value; placeholders become the empty string."""
    text = (value or "").strip()
    if text.lower() in PLACEHOLDERS:
        return ""
    return text


def canonicalize_user(value: str | None, domain: str | None = None) -> str | None:
    """Return the canonical ``domain\\user`` key, lowercased.

    Accepts NetBIOS (``DOMAIN\\user``), UPN (``user@domain``), ``domain/user``
    and bare ``user`` spellings. A bare user is combined with ``domain`` when
    given, otherwise returned on its own. Placeholders (``-``, ``n/a``,
    ``unknown``) and empty input return None.
    """
    text = _clean(value)
    if not text:
        return None
    fallback = _clean(domain).lower()
    if "\\" in text:
        domain_part, _, user_part = text.partition("\\")
        user = user_part.strip().lower()
        if not user:
            return None
        domain_part = domain_part.strip().lower()
        return f"{domain_part}\\{user}" if domain_part else user
    if "@" in text:
        local, _, upn_domain = text.partition("@")
        local = local.strip().lower()
        if not local:
            return None
        upn_domain = upn_domain.strip().lower()
        return f"{upn_domain}\\{local}" if upn_domain else local
    if "/" in text:
        domain_part, _, user_part = text.partition("/")
        user = user_part.strip().lower()
        if not user:
            return None
        domain_part = domain_part.strip().lower()
        return f"{domain_part}\\{user}" if domain_part else user
    user = text.lower()
    return f"{fallback}\\{user}" if fallback else user


def canonicalize_host(hostname: str | None) -> str | None:
    """Return the short hostname, lowercased (``WEB01.EXAMPLE.COM`` -> ``web01``).

    A value that parses as an IP address returns None: the address belongs
    in the ``ip`` key, never in ``host``. Placeholders return None.
    """
    text = _clean(hostname).lower()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return None
    short = text.removesuffix("$").split(".", 1)[0].strip()
    return short or None


def canonicalize_ip(value: str | None) -> str | None:
    """Return the canonical IP string, or None when there is no valid address.

    IPv4-mapped IPv6 addresses unwrap to IPv4 (``::ffff:10.0.0.5`` becomes
    ``10.0.0.5``); anything that is not a valid address (including
    placeholders such as ``-``) returns None.
    """
    text = _clean(value).lower()
    if not text:
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(parsed)


def compute_entity_keys(
    *,
    user: str | None = None,
    domain: str | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
) -> EntityKeys:
    """Build canonical correlation keys from raw event parts.

    This is the one shared function every OCSF event class uses: ``ip`` is
    the device address, ``src_ip``/``dst_ip`` come from the endpoints, so a
    placeholder device address never hides an endpoint address.
    """
    return EntityKeys(
        user=canonicalize_user(user, domain),
        host=canonicalize_host(hostname),
        ip=canonicalize_ip(ip),
        src_ip=canonicalize_ip(src_ip),
        dst_ip=canonicalize_ip(dst_ip),
    )


class EntityKeys(BaseModel):
    """Corvus-internal keys for deterministic correlation (not OCSF).

    Never serialized into the OCSF record: the keys travel as store
    columns and are recomputed on read (see
    ``corvus/adapters/replay/schema.py``), so conformance-checked JSON
    carries no ``entity_keys``.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    user: str | None = None
    host: str | None = None
    ip: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None


class Product(BaseModel):
    """OCSF product object: the software that emitted the event."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str
    vendor_name: str | None = None


class Extension(BaseModel):
    """OCSF schema extension object (``objects/extension.json``).

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/extension.json`` in ``ocsf-schema`` tag ``1.9.0``):
    ``name`` is the extension name (``win``), ``uid`` its unique id
    (``"2"`` as a string: the object extends ``_entity`` whose ``uid``
    is ``string_t``), and ``version`` its version (``1.9.0`` per
    ``extensions/windows/extension.json`` in the same tag, required
    there).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    uid: str | None = None
    version: str | None = None


def win_extension() -> Extension:
    """Return the win extension entry for ``metadata.extensions``."""
    return Extension(
        name=WIN_EXTENSION_NAME,
        uid=WIN_EXTENSION_UID,
        version=WIN_EXTENSION_VERSION,
    )


class Metadata(BaseModel):
    """OCSF metadata object, flattened to the fields Corvus needs.

    ``profiles`` names the schema profiles the event claims (``host``
    on every Windows mapper record, which always carries host context
    in ``device``/``actor``); profile-gated attributes count only under
    a declared profile.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    product: Product
    log_name: str | None = Field(
        default=None, description="Log source, e.g. wazuh-alerts-*"
    )
    uid: str | None = Field(default=None, description="Original event id in the SIEM")
    version: str = Field(
        default=OCSF_SCHEMA_VERSION, description="Pinned OCSF schema version"
    )
    extensions: list[Extension] | None = Field(
        default=None,
        description="Schema extensions used to construct the event "
        "(one win entry on win extension classes, nothing on core classes)",
    )
    profiles: list[str] | None = Field(
        default=None,
        description="Schema profiles the event claims "
        '("host" on records carrying device/actor context)',
    )


class Device(BaseModel):
    """OCSF device object (the host the event was observed on).

    ``type_id`` is required in the pinned OCSF 1.9.0 schema
    (``objects/device.json``; the id enum lives in ``dictionary.json``:
    0 Unknown, 99 Other). Corvus emits 0 Unknown with the caption,
    since the source never names the device type.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    hostname: str | None = None
    ip: str | None = None
    type: str | None = None
    type_id: int | None = None

    @field_validator("type_id")
    @classmethod
    def _check_type(cls, value: int | None) -> int | None:
        if value is not None and value not in (0, 99):
            raise ValueError("type_id must be 0 (Unknown) or 99 (Other)")
        return value


class Endpoint(BaseModel):
    """OCSF network endpoint (IP with an optional port)."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)


class User(BaseModel):
    """OCSF user object: the username plus the domain it is defined in."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    domain: str | None = None


class Fingerprint(BaseModel):
    """OCSF fingerprint object: one hash with its algorithm.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/fingerprint.json`` in ``ocsf-schema`` tag ``1.9.0``,
    the shape used by the file object's ``hashes`` attribute):
    ``algorithm`` is the caption of ``algorithm_id`` (``"Other"`` keeps
    the source name), and both ``algorithm_id`` and ``value`` are
    required there.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    algorithm: str | None = None
    algorithm_id: int | None = None
    value: str | None = None

    @field_validator("algorithm_id")
    @classmethod
    def _check_algorithm(cls, value: int | None) -> int | None:
        # Enum from objects/fingerprint.json attributes.algorithm_id.enum:
        # 0 Unknown, 1 MD5, 2 SHA-1, 3 SHA-256, 4 SHA-512, 5 CTPH,
        # 6 TLSH, 7 quickXorHash, 8 SHA-224, 9 SHA-384, 10 SHA-512/224,
        # 11 SHA-512/256, 12 SHA3-224, 13 SHA3-256, 14 SHA3-384,
        # 15 SHA3-512, 16 xxHash H3 64-bit, 17 xxHash H3 128-bit,
        # 18 Imphash, 19 NPF, 20 HASSH, 99 Other.
        if value is not None and value not in (
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            99,
        ):
            raise ValueError("algorithm_id must be one of 0-20 or 99 (Other)")
        return value


class File(BaseModel):
    """OCSF file object; ``name`` is derived from ``path`` when missing.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/file.json`` in ``ocsf-schema`` tag ``1.9.0``). ``signature``
    is deliberately absent: it is deprecated since 1.8.0 in favor of
    ``signatures``, so signer evidence stays verbatim in ``unmapped``.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    path: str | None = None
    name: str | None = None
    hashes: list[Fingerprint] | None = None
    desc: str | None = None
    company_name: str | None = None
    version: str | None = None
    internal_name: str | None = None
    product: Product | None = None
    type: str | None = None
    type_id: int | None = None

    @field_validator("type_id")
    @classmethod
    def _check_type(cls, value: int | None) -> int | None:
        # Enum from the pinned OCSF 1.9.0 schema (``objects/file.json``
        # ``attributes.type_id.enum``: 0 Unknown, 1 Regular File,
        # 2 Folder, 3 Character Device, 4 Block Device, 5 Local Socket,
        # 6 Named Pipe, 7 Symbolic Link, 8 Executable File, 99 Other).
        if value is not None and value not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 99):
            raise ValueError("type_id must be one of 0-8 or 99 (Other)")
        return value

    @model_validator(mode="after")
    def _derive_name(self) -> File:
        if not self.name and self.path:
            token = self.path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            self.name = token or None
        return self


class Process(BaseModel):
    """OCSF process object, with an optional parent process."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    pid: int | None = None
    name: str | None = None
    cmd_line: str | None = None
    file: File | None = None
    parent_process: Process | None = None


Process.model_rebuild()


class Actor(BaseModel):
    """OCSF actor object: the user and/or process that initiated the activity."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    user: User | None = None
    process: Process | None = None


class JobAction(BaseModel):
    """OCSF job-action object: one action a scheduled job performs.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/job_action.json`` in ``ocsf-schema`` tag ``1.9.0``):
    ``cmd_line`` is the command line the action executes, and
    ``type_id``/``type`` name the action type (required in the schema:
    0 Unknown, 1 COM Handler, 2 Execute, 3 E-mail, 4 Show Message,
    99 Other). This is the non-deprecated home for scheduled-task
    commands since 1.9.0 deprecated ``job.cmd_line`` (PR #1597) in
    favor of ``job.job_actions[].cmd_line`` (see ``objects/job.json``).
    Mappers set the type they can tell (an Exec action from task XML
    is 2 Execute); when the type is unknowable, use 0 Unknown.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    cmd_line: str | None = None
    type: str | None = None
    type_id: int | None = None

    @field_validator("type_id")
    @classmethod
    def _check_type(cls, value: int | None) -> int | None:
        if value is not None and value not in (0, 1, 2, 3, 4, 99):
            raise ValueError("type_id must be one of 0-4 or 99 (Other)")
        return value


class Job(BaseModel):
    """OCSF scheduled-job object.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/job.json`` in ``ocsf-schema`` tag ``1.9.0``). ``cmd_line``
    is deliberately absent: deprecated since 1.9.0 in favor of
    ``job_actions[].cmd_line`` — commands live in :class:`JobAction`.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    job_actions: list[JobAction] | None = None


class Module(BaseModel):
    """OCSF module object: a loaded library or driver.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/module.json`` in ``ocsf-schema`` tag ``1.9.0``): the
    loaded image lives in ``file``. No other module attribute has a
    source in the mapped Windows events.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    file: File | None = None


class OcsfEventBase(BaseModel):
    """Shared OCSF envelope; never instantiated directly."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    class_uid: int
    category_uid: int
    activity_id: int = 1
    time: int = Field(description="Event time as UTC epoch milliseconds")
    severity_id: int = 1
    metadata: Metadata
    device: Device | None = None
    actor: Actor | None = None
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    raw_data: str | None = None
    unmapped: dict[str, Any] = Field(default_factory=dict)
    entity_keys: EntityKeys = Field(default_factory=EntityKeys)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def type_uid(self) -> int:
        """OCSF type id: ``class_uid * 100 + activity_id`` (always recomputed)."""
        return self.class_uid * 100 + self.activity_id

    @field_validator("time", mode="before")
    @classmethod
    def _coerce_time(cls, value: datetime | int) -> int:
        if isinstance(value, bool):
            raise ValueError("time must be epoch milliseconds or an aware datetime")
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("time must be a timezone-aware UTC datetime")
            moment = int(value.timestamp() * 1000)
            if moment < MIN_TIME_MS:
                raise ValueError(
                    f"time {moment} is before 2000-01-01 UTC; "
                    "expected epoch milliseconds"
                )
            return moment
        if isinstance(value, int):
            if value < MIN_TIME_MS:
                raise ValueError(
                    f"time {value} is below {MIN_TIME_MS} (2000-01-01 UTC); "
                    "the value looks like epoch seconds, "
                    "expected epoch milliseconds"
                )
            return value
        raise ValueError("time must be epoch milliseconds or an aware datetime")

    @field_validator("severity_id")
    @classmethod
    def _check_severity(cls, value: int) -> int:
        if value not in (0, 1, 2, 3, 4, 5, 6, 99):
            raise ValueError("severity_id must be 0-6 or 99 (Other)")
        return value

    @field_validator("raw_data", mode="before")
    @classmethod
    def _coerce_raw_data(cls, value: Any) -> str | None:
        if value is None or isinstance(value, str):
            return value
        if isinstance(value, dict):
            return json.dumps(value)
        raise ValueError("raw_data must be a JSON string or an object")

    @model_validator(mode="after")
    def _recompute_entity_keys(self) -> OcsfEventBase:
        actor_user = self.actor.user if self.actor and self.actor.user else None
        device = self.device
        self.entity_keys = compute_entity_keys(
            user=actor_user.name if actor_user else None,
            domain=actor_user.domain if actor_user else None,
            hostname=device.hostname if device else None,
            ip=device.ip if device else None,
            src_ip=self.src_endpoint.ip if self.src_endpoint else None,
            dst_ip=self.dst_endpoint.ip if self.dst_endpoint else None,
        )
        return self


class Authentication(OcsfEventBase):
    """OCSF 3002 Authentication (category 3, Identity & Access Management).

    ``user`` is the subject being authenticated (required in the pinned
    OCSF 1.9.0 schema: ``events/iam/authentication.json``); the same
    identity also appears under ``actor.user``.
    """

    class_uid: Literal[3002] = 3002
    category_uid: Literal[3] = 3
    activity_id: int = 1
    user: User | None = None
    status: str | None = None
    status_id: int | None = None
    logon_type: str | None = None
    logon_type_id: int | None = None

    @field_validator("logon_type_id")
    @classmethod
    def _check_logon_type(cls, value: int | None) -> int | None:
        # Enum from the pinned OCSF 1.9.0 schema (`dictionary.json`,
        # `attributes.logon_type_id.enum` in `ocsf-schema` tag `1.9.0`):
        # 0 Unknown, 1 System, 2 Interactive, 3 Network, 4 Batch,
        # 5 OS Service, 7 Unlock, 8 Network Cleartext, 9 New Credentials,
        # 10 Remote Interactive, 11 Cached Interactive,
        # 12 Cached Remote Interactive, 13 Cached Unlock, 99 Other.
        if value is not None and value not in (
            0,
            1,
            2,
            3,
            4,
            5,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            99,
        ):
            raise ValueError("logon_type_id must be one of 0, 1-5, 7-13, or 99 (Other)")
        return value


class ProcessActivity(OcsfEventBase):
    """OCSF 1007 Process Activity (category 1, System Activity)."""

    class_uid: Literal[1007] = 1007
    category_uid: Literal[1] = 1
    activity_id: int = 1
    process: Process | None = None
    # Pinned OCSF 1.9.0 ``process_activity.actual_permissions`` ("the
    # permissions that were granted in a platform-native format",
    # ``dictionary.json`` types it integer_t). Corvus parses the
    # platform-native mask (e.g. a Sysmon GrantedAccess hex string) to
    # an integer; an unparseable value stays verbatim in ``unmapped``.
    actual_permissions: int | None = None


class NetworkActivity(OcsfEventBase):
    """OCSF 4001 Network Activity (category 4, Network Activity)."""

    class_uid: Literal[4001] = 4001
    category_uid: Literal[4] = 4
    activity_id: int = 1
    action: str | None = None
    action_id: int | None = None

    @field_validator("action_id")
    @classmethod
    def _check_action(cls, value: int | None) -> int | None:
        if value is not None and value not in (0, 1, 2, 99):
            raise ValueError(
                "action_id must be 0 (Unknown), 1 (Allowed), 2 (Denied), or 99 (Other)"
            )
        return value


class FileSystemActivity(OcsfEventBase):
    """OCSF 1001 File System Activity (category 1, System Activity)."""

    class_uid: Literal[1001] = 1001
    category_uid: Literal[1] = 1
    activity_id: int = 1
    file: File | None = None


class ScheduledJobActivity(OcsfEventBase):
    """OCSF 1006 Scheduled Job Activity (category 1, System Activity)."""

    class_uid: Literal[1006] = 1006
    category_uid: Literal[1] = 1
    activity_id: int = 1
    job: Job | None = None


class ScriptContent(BaseModel):
    """OCSF long-string object: script text that may be truncated.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/long_string.json`` in ``ocsf-schema`` tag ``1.9.0``):
    ``value`` (required there) is the string, ``is_truncated`` says a
    product cut it, and ``untruncated_size`` is the pre-cut byte size.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    value: str
    is_truncated: bool | None = None
    untruncated_size: int | None = None


class Script(BaseModel):
    """OCSF script object: a script executed by a shell or engine.

    Field meanings from the pinned OCSF 1.9.0 schema (``objects/script.json``
    in ``ocsf-schema`` tag ``1.9.0``): ``uid`` is the engine's execution id
    (the PowerShell ``ScriptBlockId``), ``script_content`` is the
    ``long_string`` object above (required there, always set when a
    script object is emitted), and ``type_id`` 2 with ``type``
    ``"PowerShell"`` names the PowerShell engine.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str | None = None
    name: str | None = None
    script_content: ScriptContent | None = None
    type: str | None = None
    type_id: int | None = None

    @field_validator("type_id")
    @classmethod
    def _check_type(cls, value: int | None) -> int | None:
        # Enum from objects/script.json attributes.type_id.enum: 0 Unknown,
        # 1 Windows Command Prompt, 2 PowerShell, 3 Python, 4 JavaScript,
        # 5 VBScript, 6 Unix Shell, 7 VBA, 99 Other.
        if value is not None and value not in (0, 1, 2, 3, 4, 5, 6, 7, 99):
            raise ValueError("type_id must be one of 0-7 or 99 (Other)")
        return value


class ScriptActivity(OcsfEventBase):
    """OCSF 1009 Script Activity (category 1, System Activity).

    Class and activity from the pinned OCSF 1.9.0 schema
    (``events/system/script_activity.json``: uid 9 under the system category,
    activity 1 Execute).
    """

    class_uid: Literal[1009] = 1009
    category_uid: Literal[1] = 1
    activity_id: int = 1
    script: Script | None = None


class RegKey(BaseModel):
    """OCSF reg_key object: a Windows registry key.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``extensions/windows/objects/registry_key.json`` in ``ocsf-schema``
    tag ``1.9.0``): ``path`` is the full path to the key (required
    there); the remaining attributes have no source in the mapped
    Windows events and stay empty.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    path: str | None = None


class RegValue(BaseModel):
    """OCSF reg_value object: a Windows registry value.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``extensions/windows/objects/registry_value.json`` in
    ``ocsf-schema`` tag ``1.9.0``): ``name`` is the value name and
    ``path`` the full path of the key holding it (both required
    there); ``data`` is the value data, which carries a Sysmon 13
    ``Details`` string verbatim.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    path: str | None = None
    data: str | None = None


class WinService(BaseModel):
    """OCSF win_service object: a Windows service.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``extensions/windows/objects/win_service.json`` in ``ocsf-schema``
    tag ``1.9.0``): ``name`` is the unique service name (required
    there), ``cmd_line`` the full launch command line, and
    ``service_start_name`` the account the service starts as.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    cmd_line: str | None = None
    service_start_name: str | None = None
    service_start_type: str | None = None
    service_start_type_id: int | None = None
    service_type: str | None = None
    service_type_id: int | None = None

    @field_validator("service_start_type_id")
    @classmethod
    def _check_start_type(cls, value: int | None) -> int | None:
        # Enum from the pinned OCSF 1.9.0 win extension
        # (`extensions/windows/dictionary.json`,
        # `attributes.service_start_type_id.enum` in `ocsf-schema` tag
        # `1.9.0`): 0 Unknown, 1 Boot, 2 System, 3 Auto, 4 Demand,
        # 5 Disabled, 99 Other.
        if value is not None and value not in (0, 1, 2, 3, 4, 5, 99):
            raise ValueError("service_start_type_id must be one of 0-5 or 99 (Other)")
        return value

    @field_validator("service_type_id")
    @classmethod
    def _check_service_type(cls, value: int | None) -> int | None:
        # Enum from the pinned OCSF 1.9.0 win extension
        # (`extensions/windows/dictionary.json`,
        # `attributes.service_type_id.enum` in `ocsf-schema` tag
        # `1.9.0`): 0 Unknown, 1 Kernel Driver, 2 File System Driver,
        # 3 Own Process, 4 Share Process, 99 Other.
        if value is not None and value not in (0, 1, 2, 3, 4, 99):
            raise ValueError("service_type_id must be one of 0-4 or 99 (Other)")
        return value


class RegistryKeyActivity(OcsfEventBase):
    """OCSF 201001 Registry Key Activity (category 1, System Activity).

    Class from the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/registry_key_activity.json``: uid 1,
    class ``201001``; ``extends`` system, so category 1). Activity ids
    from that file's ``activity_id`` enum: 1 Create, 2 Read, 3 Modify,
    4 Delete, 5 Rename, 6 Set Security, 7 Restore, 8 Import, 9 Export.
    The key lives in ``reg_key``; a rename also carries the pre-rename
    key in ``prev_reg_key``.
    """

    class_uid: Literal[201001] = 201001
    category_uid: Literal[1] = 1
    activity_id: int = 1
    reg_key: RegKey | None = None
    prev_reg_key: RegKey | None = None


class RegistryValueActivity(OcsfEventBase):
    """OCSF 201002 Registry Value Activity (category 1, System Activity).

    Class from the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/registry_value_activity.json``: uid 2,
    class ``201002``; ``extends`` system, so category 1). Activity ids
    from that file's ``activity_id`` enum: 1 Get, 2 Set, 3 Modify,
    4 Delete. The value lives in ``reg_value``.
    """

    class_uid: Literal[201002] = 201002
    category_uid: Literal[1] = 1
    activity_id: int = 1
    reg_value: RegValue | None = None


class WindowsServiceActivity(OcsfEventBase):
    """OCSF 201004 Windows Service Activity (category 1, System Activity).

    Class from the pinned OCSF 1.9.0 win extension
    (``extensions/windows/events/windows_service_activity.json``: uid 4,
    class ``201004``; ``extends`` system, so category 1). Activity ids
    from that file's ``activity_id`` enum: 1 Create, 2 Reconfigure,
    3 Start, 4 Stop, 5 Pause, 6 Continue, 7 Delete. The service lives
    in ``win_service``.
    """

    class_uid: Literal[201004] = 201004
    category_uid: Literal[1] = 1
    activity_id: int = 1
    win_service: WinService | None = None


class TacticRef(BaseModel):
    """OCSF tactic object: one ATT&CK tactic naming a finding's attack.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/tactic.json`` in ``ocsf-schema`` tag ``1.9.0``): ``uid``
    carries the ATT&CK tactic id (for example ``"TA0002"``) and
    ``name`` its display name (for example ``"Execution"``).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str | None = None
    name: str | None = None


class TechniqueRef(BaseModel):
    """OCSF technique object: one ATT&CK technique or sub-technique.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/technique.json`` and ``objects/sub_technique.json`` in
    ``ocsf-schema`` tag ``1.9.0``): ``uid`` is the technique id (for
    example ``"T1059.001"``), ``name`` its display name.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str | None = None
    name: str | None = None


class AttackRef(BaseModel):
    """OCSF attack object: tactic plus technique behind a finding.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/attack.json`` in ``ocsf-schema`` tag ``1.9.0``):
    ``tactic`` and ``technique`` are recommended, and at least one of
    the two is required there; ``version`` names the ATT&CK matrix
    version the ids resolve against. A sub-technique finding carries
    the parent technique in ``technique`` and the sub-technique in
    ``sub_technique``.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    tactic: TacticRef | None = None
    technique: TechniqueRef | None = None
    sub_technique: TechniqueRef | None = None
    version: str | None = None


class Analytic(BaseModel):
    """OCSF analytic object: the detection logic behind a finding.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/analytic.json`` in ``ocsf-schema`` tag ``1.9.0``):
    ``name`` is the analytic name, ``uid`` its unique id, and
    ``type_id`` 1 with ``type`` ``"Rule"`` names a Sigma-derived rule
    (``type_id`` is required there: 0 Unknown, 1 Rule, 2 Behavioral,
    3 Statistical, 4 Learning (ML/DL), 5 Fingerprinting, 6 Tagging,
    7 Keyword Match, 8 Regular Expressions, 9 Exact Data Match,
    10 Partial Data Match, 11 Indexed Data Match, 99 Other).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    uid: str | None = None
    desc: str | None = None
    type: str | None = None
    type_id: int | None = None

    @field_validator("type_id")
    @classmethod
    def _check_type(cls, value: int | None) -> int | None:
        if value is not None and value not in (
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            99,
        ):
            raise ValueError("type_id must be one of 0-11 or 99 (Other)")
        return value


class RelatedEvent(BaseModel):
    """OCSF related-event object: one event behind a finding.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/related_event.json`` in ``ocsf-schema`` tag ``1.9.0``):
    ``uid`` (required there) is the related event's OCSF uid and
    ``type_uid`` its OCSF type id.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str | None = None
    type_uid: int | None = None


class Evidence(BaseModel):
    """OCSF evidence object: context of one event behind a finding.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/evidences.json`` in ``ocsf-schema`` tag ``1.9.0``): the
    matched event's actor, process, endpoints, device and file. Every
    attribute is optional there; Corvus sets ``uid`` to the matched
    event's OCSF uid and fills whichever context the event carries.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str | None = None
    actor: Actor | None = None
    process: Process | None = None
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    device: Device | None = None
    file: File | None = None


class FindingInfo(BaseModel):
    """OCSF finding-info object: supporting info about a finding.

    Attribute names from the pinned OCSF 1.9.0 schema
    (``objects/finding_info.json`` in ``ocsf-schema`` tag ``1.9.0``,
    which has no ``evidences`` attribute): ``uid`` is required there
    and carries the finding uid; ``title`` and ``analytic`` are
    recommended. ``attacks`` holds the resolved ATT&CK tactic/technique
    pairs; ``related_events`` holds the matched event uids; ``src_url``
    points at the rule source.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str | None = None
    title: str | None = None
    desc: str | None = None
    analytic: Analytic | None = None
    attacks: list[AttackRef] | None = None
    related_events: list[RelatedEvent] | None = None
    src_url: str | None = None


class DetectionFinding(OcsfEventBase):
    """OCSF 2004 Detection Finding (category 2, Findings).

    Class from the pinned OCSF 1.9.0 schema
    (``events/findings/detection_finding.json``: uid 4, ``extends``
    finding, so category 2). Activity ids from the base finding event
    (``events/findings/finding.json``): 1 Create, 2 Update, 3 Close.
    ``status_id`` 1 with ``status`` ``"New"`` marks a freshly created
    finding (enum from the same file: 1 New, 2 In Progress,
    3 Suppressed, 4 Resolved, 5 Archived, 6 Deleted). ``severity``
    carries the caption of ``severity_id`` (1 Informational, 2 Low,
    3 Medium, 4 High, 5 Critical, from ``dictionary.json`` in the
    pinned tag). Rule metadata the typed slots cannot hold (the Sigma
    author, needed for Detection Rule License attribution) stays in
    ``unmapped`` under the ``sigma_`` prefix, never in typed fields.
    ``evidences`` (from ``events/findings/detection_finding.json`` in
    the pinned tag, not from ``finding_info``) holds one entry per
    matched event with that event's context.
    """

    class_uid: Literal[2004] = 2004
    category_uid: Literal[2] = 2
    activity_id: int = 1
    severity: str | None = None
    status: str | None = None
    status_id: int | None = None
    start_time: int | None = None
    end_time: int | None = None
    finding_info: FindingInfo | None = None
    evidences: list[Evidence] | None = None

    @field_validator("status_id")
    @classmethod
    def _check_status(cls, value: int | None) -> int | None:
        # Enum from the pinned OCSF 1.9.0 schema
        # (``events/findings/finding.json``
        # ``attributes.status_id.enum`` in ``ocsf-schema`` tag
        # ``1.9.0``): 1 New, 2 In Progress, 3 Suppressed, 4 Resolved,
        # 5 Archived, 6 Deleted.
        if value is not None and value not in (1, 2, 3, 4, 5, 6):
            raise ValueError("status_id must be one of 1-6")
        return value

    @field_validator("start_time", "end_time", mode="before")
    @classmethod
    def _coerce_finding_time(cls, value: datetime | int | None) -> int | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("time must be a timezone-aware UTC datetime")
            moment = int(value.timestamp() * 1000)
        elif isinstance(value, int):
            moment = value
        else:
            raise ValueError("time must be epoch milliseconds or an aware datetime")
        if moment < MIN_TIME_MS:
            raise ValueError(f"time {moment} is below {MIN_TIME_MS} (2000-01-01 UTC)")
        return moment


class ModuleActivity(OcsfEventBase):
    """OCSF 1005 Module Activity (category 1, System Activity).

    Class and activity from the pinned OCSF 1.9.0 schema
    (``events/system/module_activity.json``: uid 5 under the system
    category, activity 1 Load). The loaded image lives in
    ``module.file``; the loading process is ``actor.process``.
    """

    class_uid: Literal[1005] = 1005
    category_uid: Literal[1] = 1
    activity_id: int = 1
    module: Module | None = None


OcsfEvent = Annotated[
    Authentication
    | ProcessActivity
    | NetworkActivity
    | FileSystemActivity
    | ScheduledJobActivity
    | ScriptActivity
    | ModuleActivity
    | RegistryKeyActivity
    | RegistryValueActivity
    | WindowsServiceActivity
    | DetectionFinding,
    Field(discriminator="class_uid"),
]
