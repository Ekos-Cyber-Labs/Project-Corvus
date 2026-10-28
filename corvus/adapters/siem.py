"""SIEM adapter interface and in-memory fake.

The core depends only on :class:`SiemAdapter` (``docs/architecture.md``);
``WazuhAdapter`` and ``ReplayAdapter`` implement this protocol elsewhere.
:class:`FakeAdapter` serves in-memory OCSF events for tests and records
every rule and list call made against it.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterable
from datetime import timedelta
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable
from xml.sax.saxutils import escape

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from corvus.normalize.ocsf import (
    OcsfEvent,
    canonicalize_host,
    canonicalize_ip,
    canonicalize_user,
)

__all__ = [
    "DEFAULT_STREAM_PAGE_SIZE",
    "MAX_QUERY_LIMIT",
    "MAX_STREAM_PAGE_SIZE",
    "Cursor",
    "DeployMode",
    "Deployment",
    "Entity",
    "FakeAdapter",
    "Indicator",
    "NativeRule",
    "SiemAdapter",
    "SigmaRule",
    "SourceCategory",
    "SourceEntry",
    "SourceInventory",
    "ValidationResult",
]

#: Hard cap for ``query_events`` (architecture: ``limit <= 200``).
MAX_QUERY_LIMIT = 200

#: Local Wazuh rule id range translation targets must stay inside.
RULE_ID_MIN = 100000
RULE_ID_MAX = 120000

#: Deployment mode for ``deploy_rule``.
DeployMode = Literal["shadow", "active"]

#: Telemetry category per inventory source (architecture section 5).
SourceCategory = Literal[
    "endpoint process",
    "authentication",
    "network",
    "web/WAF",
    "IPS",
    "EDR",
    "other",
]

#: Explicit (product, log source) -> inventory category.
_SOURCE_CATEGORY: dict[tuple[str, str], SourceCategory] = {
    ("wazuh", "Security"): "authentication",
    ("wazuh", "Microsoft-Windows-Sysmon/Operational"): "endpoint process",
    ("wazuh", "suricata"): "network",
    ("wazuh", "syscheck"): "endpoint process",
}

#: OCSF class -> inventory category fallback for unmapped sources.
_CLASS_CATEGORY: dict[int, SourceCategory] = {
    1007: "endpoint process",
    3002: "authentication",
    4001: "network",
    1001: "endpoint process",
    1006: "endpoint process",
    2004: "other",
}

#: Hard cap for ``stream_alerts`` pages.
MAX_STREAM_PAGE_SIZE = 1000

#: Default ``stream_alerts`` page size.
DEFAULT_STREAM_PAGE_SIZE = 500


class Cursor(BaseModel):
    """Opaque ingestion checkpoint (``search_after`` state)."""

    model_config = ConfigDict(frozen=True)

    last_time: int | None = None
    last_uid: str | None = None


class Entity(BaseModel):
    """Principal filter for ``query_events``.

    Every set field must match (AND); pass ``entity=None`` for no filter.
    Inputs are canonicalized on the way in, so ``WEB01`` matches
    ``web01.example.com``. A provided field that canonicalizes to nothing
    (a placeholder like ``-``, or an IP passed as ``host``) raises instead
    of silently matching everything. ``EXAMPLE\\jdoe`` and
    ``jdoe@example.com`` canonicalize differently (``example\\jdoe`` vs
    ``example.com\\jdoe``) and do not match each other; NetBIOS-to-DNS
    domain matching needs the entity alias dictionary, which comes later.
    ``ip`` matches the device address or either endpoint address.
    """

    model_config = ConfigDict(frozen=True)

    host: str | None = None
    user: str | None = None
    ip: str | None = None

    @field_validator("host", mode="before")
    @classmethod
    def _normalize_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = canonicalize_host(value)
        if normalized is None:
            raise ValueError(f"host {value!r} is a placeholder or an IP address")
        return normalized

    @field_validator("user", mode="before")
    @classmethod
    def _normalize_user(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = canonicalize_user(value)
        if normalized is None:
            raise ValueError(f"user {value!r} is a placeholder")
        return normalized

    @field_validator("ip", mode="before")
    @classmethod
    def _normalize_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = canonicalize_ip(value)
        if normalized is None:
            raise ValueError(f"ip {value!r} is not a valid address")
        return normalized

    @model_validator(mode="after")
    def _require_a_filter(self) -> Entity:
        if self.host is None and self.user is None and self.ip is None:
            raise ValueError("Entity needs a host, user, or ip (use entity=None)")
        return self


class SigmaRule(BaseModel):
    """A proposed detection in Sigma source format."""

    model_config = ConfigDict(frozen=True)

    title: str
    yaml: str


class NativeRule(BaseModel):
    """A Sigma rule translated to the SIEM native format (Wazuh XML)."""

    model_config = ConfigDict(frozen=True)

    rule_id: int = Field(ge=RULE_ID_MIN, le=RULE_ID_MAX)
    xml: str
    source_title: str | None = None


class ValidationResult(BaseModel):
    """Outcome of checking a native rule against sample events."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    errors: list[str] = Field(default_factory=list)
    matched_uids: list[str] = Field(default_factory=list)
    false_positive_count: int = 0


class Deployment(BaseModel):
    """Handle for a rule deployed to the SIEM."""

    model_config = ConfigDict(frozen=True)

    deployment_id: str
    rule_id: int = Field(ge=RULE_ID_MIN, le=RULE_ID_MAX)
    mode: DeployMode


class Indicator(BaseModel):
    """One expirable indicator for a CDB-style list (never embedded in rules)."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["ip", "domain", "hash"]
    value: str


class SourceEntry(BaseModel):
    """Telemetry actually observed for one product/log source."""

    model_config = ConfigDict(frozen=True)

    source: str
    category: SourceCategory
    product: str
    decoder: str | None = None
    classes: list[int] = Field(default_factory=list)
    host_count: int = 0
    event_count: int = 0
    first_seen: int = 0
    last_seen: int = 0


class SourceInventory(BaseModel):
    """What telemetry exists, computed from the data, never configured."""

    model_config = ConfigDict(frozen=True)

    sources: list[SourceEntry] = Field(default_factory=list)


@runtime_checkable
class SiemAdapter(Protocol):
    """The only interface the core needs from a SIEM (Wazuh or replay)."""

    def stream_alerts(
        self,
        since: Cursor | None = None,
        page_size: int = DEFAULT_STREAM_PAGE_SIZE,
    ) -> tuple[list[OcsfEvent], Cursor]:
        """Return up to ``page_size`` events after ``since`` and the cursor.

        Every event carries a stable, unique ``metadata.uid``; ordering
        ties break on it and the cursor advances to the last returned
        event. Real adapters must page on an ingestion-ordered key
        (``search_after``), never wall time alone, so late-indexed events
        are not skipped.
        """
        ...

    def query_events(
        self,
        entity: Entity | None = None,
        start: int | None = None,
        end: int | None = None,
        classes: list[int] | None = None,
        limit: int = 200,
    ) -> list[OcsfEvent]:
        """Return up to ``limit`` (<= 200) matching events, oldest first.

        ``start``/``end`` are an inclusive time window; ``start`` after
        ``end`` raises.
        """
        ...

    def translate_rule(self, sigma: SigmaRule) -> NativeRule:
        """Translate a Sigma rule to the SIEM native format (Wazuh XML)."""
        ...

    def validate_rule(
        self, native: NativeRule, samples: list[OcsfEvent]
    ) -> ValidationResult:
        """Check a native rule against sample events (backtest)."""
        ...

    def deploy_rule(self, native: NativeRule, mode: DeployMode) -> Deployment:
        """Deploy a rule in ``shadow`` (log-only) or ``active`` mode."""
        ...

    def rollback_rule(self, deployment: Deployment) -> None:
        """Remove a previous deployment; safe to repeat."""
        ...

    def update_list(
        self,
        name: str,
        indicators: list[Indicator],
        ttl: timedelta | None = None,
    ) -> int:
        """Stage expiring indicators (``[ROADMAP]`` CDB lists); return count.

        Roadmap (AGENTS.md rule 8): real adapters raise NotImplementedError
        until indicator lists are in scope; the fake records calls for tests.
        """
        ...

    def describe_sources(
        self, window: tuple[int, int] | None = None
    ) -> SourceInventory:
        """Report telemetry actually present, computed from the data."""
        ...


def _event_order(event: OcsfEvent) -> tuple[int, str]:
    """Sort/resume key: event time, then SIEM uid for equal timestamps."""
    return (event.time, event.metadata.uid or "")


def _matches_event(
    event: OcsfEvent,
    entity: Entity | None,
    start: int | None,
    end: int | None,
    classes: set[int] | None,
) -> bool:
    """Check one event against the ``query_events`` filters."""
    if start is not None and event.time < start:
        return False
    if end is not None and event.time > end:
        return False
    if classes is not None and event.class_uid not in classes:
        return False
    if entity is None:
        return True
    keys = event.entity_keys
    if entity.host is not None and keys.host != entity.host:
        return False
    if entity.user is not None and keys.user != entity.user:
        return False
    if entity.ip is not None and entity.ip not in {keys.ip, keys.src_ip, keys.dst_ip}:
        return False
    return True


def _category_for_source(
    product: str, log_name: str, classes: list[int], events: list[OcsfEvent]
) -> SourceCategory:
    """Pick the inventory category from the source map, else the classes."""
    known = _SOURCE_CATEGORY.get((product, log_name))
    if known is not None:
        return known
    return _category_for_classes(classes, events)


def _category_for_classes(
    classes: list[int], events: list[OcsfEvent]
) -> SourceCategory:
    """Pick the category of the most common class (ties: smallest uid)."""
    counts: dict[int, int] = {}
    for event in events:
        counts[event.class_uid] = counts.get(event.class_uid, 0) + 1
    top = min(classes, key=lambda uid: (-counts[uid], uid))
    return _CLASS_CATEGORY.get(top, "endpoint process")


class FakeAdapter:
    """In-memory :class:`SiemAdapter` for tests.

    Serves a fixed event list ordered by ``(time, uid)`` and records every
    rule and list call. Validation only checks XML well-formedness: it is
    not a backtest; the real backtest lives in the Wazuh/replay adapters.
    """

    def __init__(self, events: Iterable[OcsfEvent] = ()) -> None:
        stored = list(events)
        missing = sum(1 for event in stored if not event.metadata.uid)
        if missing:
            raise ValueError(
                f"FakeAdapter needs a stable metadata.uid per event "
                f"({missing} have none); resume ties break on it"
            )
        self._events: list[OcsfEvent] = sorted(stored, key=_event_order)
        self.translate_calls: list[SigmaRule] = []
        self.validate_calls: list[tuple[NativeRule, list[OcsfEvent]]] = []
        self.deploy_calls: list[tuple[NativeRule, DeployMode]] = []
        self.rollback_calls: list[Deployment] = []
        self.update_list_calls: list[tuple[str, list[Indicator], timedelta | None]] = []
        self._translated = 0
        self._deployed = 0

    def stream_alerts(
        self,
        since: Cursor | None = None,
        page_size: int = DEFAULT_STREAM_PAGE_SIZE,
    ) -> tuple[list[OcsfEvent], Cursor]:
        """Return up to ``page_size`` events after ``since`` (no resume gaps)."""
        if page_size < 1 or page_size > MAX_STREAM_PAGE_SIZE:
            raise ValueError(
                f"page_size must be 1..{MAX_STREAM_PAGE_SIZE}, got {page_size}"
            )
        if since is None or since.last_time is None:
            eligible = list(self._events)
        else:
            floor = (since.last_time, since.last_uid or "")
            eligible = [e for e in self._events if _event_order(e) > floor]
        page = eligible[:page_size]
        if page:
            last = page[-1]
            cursor = Cursor(last_time=last.time, last_uid=last.metadata.uid)
        else:
            cursor = since if since is not None else Cursor()
        return page, cursor

    def query_events(
        self,
        entity: Entity | None = None,
        start: int | None = None,
        end: int | None = None,
        classes: list[int] | None = None,
        limit: int = 200,
    ) -> list[OcsfEvent]:
        """Filter by entity (AND), inclusive time window, classes, cap."""
        if limit < 1 or limit > MAX_QUERY_LIMIT:
            raise ValueError(f"limit must be 1..{MAX_QUERY_LIMIT}, got {limit}")
        if start is not None and end is not None and start > end:
            raise ValueError(f"start {start} is after end {end}")
        wanted = set(classes) if classes is not None else None
        matched = [
            event
            for event in self._events
            if _matches_event(event, entity, start, end, wanted)
        ]
        return matched[:limit]

    def translate_rule(self, sigma: SigmaRule) -> NativeRule:
        """Mint the next in-range rule id with a minimal rule skeleton."""
        self.translate_calls.append(sigma)
        span = RULE_ID_MAX - RULE_ID_MIN + 1
        rule_id = RULE_ID_MIN + (self._translated % span)
        self._translated += 1
        xml = (
            '<group name="corvus">\n'
            f'  <rule id="{rule_id}" level="10">\n'
            f"    <description>{escape(sigma.title)}</description>\n"
            "  </rule>\n"
            "</group>\n"
        )
        return NativeRule(rule_id=rule_id, xml=xml, source_title=sigma.title)

    def validate_rule(
        self, native: NativeRule, samples: list[OcsfEvent]
    ) -> ValidationResult:
        """Record the call; accept well-formed, non-empty XML."""
        self.validate_calls.append((native, list(samples)))
        errors: list[str] = []
        if not native.xml.strip():
            errors.append("native rule XML is empty")
        else:
            try:
                ET.fromstring(native.xml)
            except ET.ParseError as exc:
                errors.append(f"native rule XML does not parse: {exc}")
        return ValidationResult(valid=not errors, errors=errors)

    def deploy_rule(self, native: NativeRule, mode: DeployMode) -> Deployment:
        """Record the deployment and return a synthetic handle."""
        self.deploy_calls.append((native, mode))
        self._deployed += 1
        return Deployment(
            deployment_id=f"fake-{native.rule_id}-{mode}-{self._deployed}",
            rule_id=native.rule_id,
            mode=mode,
        )

    def rollback_rule(self, deployment: Deployment) -> None:
        """Record the rollback; repeating it is a no-op."""
        self.rollback_calls.append(deployment)

    def update_list(
        self,
        name: str,
        indicators: list[Indicator],
        ttl: timedelta | None = None,
    ) -> int:
        """Record the staged indicators; return how many were staged."""
        self.update_list_calls.append((name, list(indicators), ttl))
        return len(indicators)

    def describe_sources(
        self, window: tuple[int, int] | None = None
    ) -> SourceInventory:
        """Group stored events by product/log source within ``window``."""
        events = self._events
        if window is not None:
            first, last = window
            if first > last:
                raise ValueError(f"window start {first} is after end {last}")
            events = [e for e in events if first <= e.time <= last]
        grouped: dict[tuple[str, str], list[OcsfEvent]] = {}
        for event in events:
            key = (event.metadata.product.name, event.metadata.log_name or "")
            grouped.setdefault(key, []).append(event)
        entries = []
        for (product, log_name), group in sorted(grouped.items()):
            uids: set[int] = {e.class_uid for e in group}
            classes = sorted(uids)
            hosts = {e.entity_keys.host for e in group} - {None}
            entries.append(
                SourceEntry(
                    source=f"{product}:{log_name}" if log_name else product,
                    category=_category_for_source(product, log_name, classes, group),
                    product=product,
                    decoder=log_name or None,
                    classes=classes,
                    host_count=len(hosts),
                    event_count=len(group),
                    first_seen=min(e.time for e in group),
                    last_seen=max(e.time for e in group),
                )
            )
        return SourceInventory(sources=entries)


if TYPE_CHECKING:
    # Fails `make lint` if FakeAdapter drifts from the Protocol
    # (mypy only checks corvus/, so tests cannot carry this assertion).
    _: type[SiemAdapter] = FakeAdapter
