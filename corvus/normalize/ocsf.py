"""Pinned OCSF event models for Corvus normalization.

Everything inside Corvus is OCSF at the version pinned by
``OCSF_SCHEMA_VERSION``. Field names and activity IDs match the OCSF 1.4.0
schema (schema.ocsf.io, ``ocsf-schema`` tag ``v1.4.0``): ``actor.user``,
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

OCSF_SCHEMA_VERSION = "1.4.0"

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
    "Authentication",
    "DetectionFinding",
    "Device",
    "Endpoint",
    "EntityKeys",
    "File",
    "FileSystemActivity",
    "Job",
    "Metadata",
    "NetworkActivity",
    "OcsfEvent",
    "OcsfEventBase",
    "Process",
    "ProcessActivity",
    "Product",
    "ScheduledJobActivity",
    "User",
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
    """Corvus extension: canonical keys for deterministic correlation."""

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


class Metadata(BaseModel):
    """OCSF metadata object, flattened to the fields Corvus needs."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    product: Product
    log_name: str | None = Field(
        default=None, description="Log source, e.g. wazuh-alerts-*"
    )
    uid: str | None = Field(default=None, description="Original event id in the SIEM")
    version: str = Field(
        default=OCSF_SCHEMA_VERSION, description="Pinned OCSF schema version"
    )


class Device(BaseModel):
    """OCSF device object (the host the event was observed on)."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    hostname: str | None = None
    ip: str | None = None


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


class File(BaseModel):
    """OCSF file object; ``name`` is derived from ``path`` when missing."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    path: str | None = None
    name: str | None = None

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


class Job(BaseModel):
    """OCSF scheduled-job object."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str | None = None
    cmd_line: str | None = None


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
    """OCSF 3002 Authentication (category 3, Identity & Access Management)."""

    class_uid: Literal[3002] = 3002
    category_uid: Literal[3] = 3
    activity_id: int = 1
    status: str | None = None
    status_id: int | None = None


class ProcessActivity(OcsfEventBase):
    """OCSF 1007 Process Activity (category 1, System Activity)."""

    class_uid: Literal[1007] = 1007
    category_uid: Literal[1] = 1
    activity_id: int = 1
    process: Process | None = None


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


class DetectionFinding(OcsfEventBase):
    """OCSF 2004 Detection Finding (category 2, Findings)."""

    class_uid: Literal[2004] = 2004
    category_uid: Literal[2] = 2
    activity_id: int = 1


OcsfEvent = Annotated[
    Authentication
    | ProcessActivity
    | NetworkActivity
    | FileSystemActivity
    | ScheduledJobActivity
    | DetectionFinding,
    Field(discriminator="class_uid"),
]
