"""Logsource-to-OCSF mapping for the Corvus replay detector.

Each Sigma ``logsource`` routes to one group: an OCSF slice (class,
activity, log channel) plus a field map from Sigma field names to
value extractors over the stored OCSF record. A Sigma field with no
faithful source in the slice is absent from the map, and any rule
using it is skipped and counted with the field name, never evaluated
against null.

Typed slots are read from the OCSF record; anything the Windows
normalizer (``corvus/normalize/windows.py``) left in ``unmapped`` is
read under its original record name. Fields the normalizer consumed
without a typed equivalent (``ProcessId``, ``UtcTime``, envelope
keys) have no extractor anywhere: rules using them are skipped.

The per-logsource table is documented in ``docs/ocsf.md``; this
module is the executable form of that table.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from corvus.detect.backend import FULLTEXT_COLUMN
from corvus.normalize.windows import wire_fields

__all__ = [
    "MAPPED_SERVICE_EVENT_IDS",
    "Extractor",
    "GroupDef",
    "GROUPS",
    "UNKNOWN",
    "actor_user",
    "as_text",
    "classify_ps_subtype",
    "event_id_for",
    "extract_row",
    "hashes_sysmon_form",
    "provider_for",
    "registry_target",
    "route_logsource",
]

#: Extractor: OCSF event dict (parsed ``event_json``) to a TEXT value.
Extractor = Callable[[dict[str, Any]], str | None]

#: Sentinel for "no faithful source": routes the rule to the skip pile.
UNKNOWN = "unknown"


def _raw_record(event: dict[str, Any]) -> dict[str, Any] | None:
    """Return the parsed raw record, or None when it is not a mapping.

    The engine hands over parsed ``event_json`` dicts; ``raw_data``
    there is the JSON-encoded original record (a string) or, in
    hand-built fixtures, already a mapping. Anything else (or broken
    JSON) means no raw fallback for this row.
    """
    raw = event.get("raw_data")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        if isinstance(parsed, dict):
            return parsed
        return dict(parsed) if isinstance(parsed, Mapping) else None
    return None


def _raw_text(fields: Mapping[str, Any] | None, name: str) -> str | None:
    """Read one wire value from the pre-mapper payload for a null column.

    ``fields`` is the payload the normalizer's own layout dispatch
    rebuilt from the raw record (see :func:`wire_fields` in
    ``corvus/normalize/windows.py``): when the normalizer replaced a
    placeholder (``-``, empty, ``n/a``, ``unknown``) with null in a
    typed slot, the value the source logged is still there under the
    wire name (which is the Sigma field name). That value is what
    Sigma would compare, so the row carries it verbatim — placeholders
    included. A field truly absent from the payload (or null, or
    structured) stays null.
    """
    if fields is None:
        return None
    value = fields.get(name)
    if value is None or isinstance(value, (Mapping, list)):
        return None
    return as_text(value)


def as_text(value: object) -> str | None:
    """Coerce a stored value to TEXT for comparison.

    ``None`` stays null (a null field matches no value but satisfies
    ``NOT`` per Sigma semantics); booleans render lowercase
    (``true``/``false``, the form Sigma rules compare); numbers render
    plain; strings pass through verbatim; anything structured renders
    as JSON.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _dig(event: Mapping[str, Any], *path: str) -> Any:
    """Walk nested dicts; ``None`` when any step is missing or unmapped."""
    current: Any = event
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def typed(*path: str) -> Extractor:
    """Extractor reading a typed OCSF path, coerced to TEXT."""

    def read(event: dict[str, Any]) -> str | None:
        return as_text(_dig(event, *path))

    return read


def unmapped(name: str) -> Extractor:
    """Extractor reading one original record field from ``unmapped``."""

    def read(event: dict[str, Any]) -> str | None:
        raw = event.get("unmapped")
        if not isinstance(raw, Mapping):
            return None
        return as_text(raw.get(name))

    return read


def const(value: str) -> Extractor:
    """Extractor returning a fixed value (channel-derived constants)."""

    def read(event: dict[str, Any]) -> str | None:
        return value

    return read


def actor_user(event: dict[str, Any]) -> str | None:
    """Reconstruct the ``DOMAIN\\user`` account from the typed actor."""
    user = _dig(event, "actor", "user")
    if not isinstance(user, Mapping):
        return None
    name = user.get("name")
    domain = user.get("domain")
    if name is None and domain is None:
        return None
    if domain is None:
        return as_text(name)
    if name is None:
        return as_text(domain)
    return f"{domain}\\{name}"


#: Provider names per log channel, verified against the stored
#: ``raw_data`` of each slice on 2026-10-28 (see the detect report).
PROVIDERS: dict[str, str] = {
    "Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon",
    "Security": "Microsoft-Windows-Security-Auditing",
    "System": "Service Control Manager",
    "Microsoft-Windows-TaskScheduler/Operational": "Microsoft-Windows-TaskScheduler",
    "Microsoft-Windows-PowerShell/Operational": "Microsoft-Windows-PowerShell",
    "Windows PowerShell": "PowerShell",
}


def provider_for(log_name: str) -> Extractor:
    """Extractor for the Sigma ``Provider_Name`` field (channel const)."""
    return const(PROVIDERS[log_name])


#: Sysmon algorithm ids back to Sysmon ``Hashes`` spellings (the
#: ``algorithm`` caption uses ``SHA-1``/``SHA-256`` with a dash, the
#: raw Sysmon pair form does not).
_HASH_NAMES: dict[int, str] = {1: "MD5", 2: "SHA1", 3: "SHA256", 18: "IMPHASH"}


def hashes_sysmon_form(event: dict[str, Any]) -> str | None:
    """Rebuild the Sysmon ``Hashes`` pair string from fingerprints.

    Image-load rules match the raw ``IMPHASH=<hex>`` pair form, which
    the normalizer parses into typed fingerprints (dropping the raw
    string). The pair set rebuilds exactly (``ALG=value`` joined by
    commas); order is irrelevant to the ``contains`` matching rules
    use. Returns null when the event carries no hashes.
    """
    hashes = _dig(event, "module", "file", "hashes")
    if not isinstance(hashes, list) or not hashes:
        return None
    pairs = []
    for item in hashes:
        if not isinstance(item, Mapping):
            continue
        value = item.get("value")
        if value is None:
            continue
        algorithm_id = item.get("algorithm_id")
        name: object = (
            _HASH_NAMES.get(algorithm_id)
            if isinstance(algorithm_id, int)
            else item.get("algorithm")
        )
        if not isinstance(name, str) or not name:
            continue
        pairs.append(f"{name}={value}")
    return ",".join(pairs) if pairs else None


def registry_target(event: dict[str, Any]) -> str | None:
    """The Sigma ``TargetObject`` path for a registry event.

    Rename events (activity 5) report the pre-rename path in
    ``TargetObject`` on the wire, so the column reads
    ``prev_reg_key`` there and the (new) key or value path otherwise.
    """
    if event.get("activity_id") == 5:
        return as_text(_dig(event, "prev_reg_key", "path"))
    return (
        as_text(_dig(event, "reg_key", "path"))
        or as_text(_dig(event, "reg_value", "path"))
        or unmapped("TargetObject")(event)
    )


def rename_new_name(event: dict[str, Any]) -> str | None:
    """The Sigma ``NewName`` path: set on rename events only.

    Reading ``reg_key.path`` unconditionally would match ``NewName``
    rules against the key path of non-rename events, which carry no
    ``NewName`` on the wire; those stay null here.
    """
    if event.get("activity_id") != 5:
        return None
    return as_text(_dig(event, "reg_key", "path"))


def classify_ps_subtype(event: dict[str, Any]) -> str | None:
    """Classify a PowerShell-Operational script event as 4103 or 4104.

    Markers first (4104 events carry a script block id and/or the
    ``MessageNumber`` split-block key; 4103 module events carry
    ``ContextInfo``), falling back to the ``EventID`` in ``raw_data``
    for the few records carrying neither marker. Returns ``"4103"``,
    ``"4104"``, or None when the subtype cannot be told.
    """
    script = event.get("script")
    uid = script.get("uid") if isinstance(script, Mapping) else None
    raw_unmapped = event.get("unmapped")
    unmapped_keys = set(raw_unmapped) if isinstance(raw_unmapped, Mapping) else set()
    if uid is not None:
        return "4104"
    if "ContextInfo" in unmapped_keys:
        return "4103"
    if "MessageNumber" in unmapped_keys:
        return "4104"
    try:
        raw = json.loads(event.get("raw_data") or "{}")
    except ValueError, TypeError:
        return None
    if not isinstance(raw, Mapping):
        return None
    event_id: Any = raw.get("EventID", raw.get("event_id"))
    winlog = raw.get("winlog")
    if event_id is None and isinstance(winlog, Mapping):
        event_id = winlog.get("event_id")
    try:
        number = int(str(event_id).strip())  # type: ignore[union-attr]
    except ValueError, TypeError, AttributeError:
        return None
    if number == 4103:
        return "4103"
    if number == 4104:
        return "4104"
    return None


def _script_content(subtype: str) -> Extractor:
    """The script text when the event is of ``subtype``, else null.

    The text lives in the schema ``long_string`` object
    (``script_content.value``); a plain string is also accepted so rows
    stored before the object form still match.
    """

    def read(event: dict[str, Any]) -> str | None:
        if classify_ps_subtype(event) != subtype:
            return None
        content = _dig(event, "script", "script_content")
        if isinstance(content, Mapping):
            content = content.get("value")
        return as_text(content)

    return read


def _ps_event_id(event: dict[str, Any]) -> str | None:
    subtype = classify_ps_subtype(event)
    return subtype


#: (class_uid, activity_id) to EventID for service slices, where the
#: channel plus the OCSF class/activity identify the Windows event
#: exactly. Registry slices are absent on purpose: a value-Set row
#: cannot tell Sysmon 12 from 13, so ``EventID`` has no extractor
#: there and rules using it are skipped with the field name.
SERVICE_EVENT_IDS: dict[tuple[int, int], int] = {
    (3002, 1): 4624,
    (3002, 2): 4625,
    (1006, 1): 4698,
    (201004, 1): 4697,
}

SYSTEM_EVENT_IDS: dict[tuple[int, int], int] = {(201004, 1): 7045}

TASK_EVENT_IDS: dict[tuple[int, int], int] = {(1006, 1): 106}


def event_id_for(table: Mapping[tuple[int, int], int]) -> Extractor:
    """Extractor for the Sigma ``EventID`` field on service slices."""

    def read(event: dict[str, Any]) -> str | None:
        class_uid = event.get("class_uid")
        activity_id = event.get("activity_id")
        if not isinstance(class_uid, int) or not isinstance(activity_id, int):
            return None
        number = table.get((class_uid, activity_id))
        return None if number is None else str(number)

    return read


#: Sigma logsource services whose rules route by their ``EventID``
#: selection; any other selected EventID has no mapped telemetry and
#: the rule is skipped and counted per EventID.
MAPPED_SERVICE_EVENT_IDS: dict[str, frozenset[int]] = {
    "security": frozenset({4624, 4625, 4697, 4698}),
    "system": frozenset({7045}),
    "taskscheduler": frozenset({106}),
}


def _standard(log_name: str, event_id: Extractor | None = None) -> dict[str, Extractor]:
    """Channel/Provider columns plus ``EventID`` where derivable."""
    columns: dict[str, Extractor] = {
        "Channel": typed("metadata", "log_name"),
        "Provider_Name": provider_for(log_name),
    }
    if event_id is not None:
        columns["EventID"] = event_id
    return columns


@dataclass(frozen=True)
class GroupDef:
    """One routable logsource: the OCSF slice plus its field map."""

    name: str
    class_uids: frozenset[int]
    activity_ids: frozenset[int] | None
    log_names: frozenset[str]
    fields: dict[str, Extractor] = field(default_factory=dict)


def _group(
    name: str,
    class_uids: set[int],
    activity_ids: set[int] | None,
    log_name: str,
    fields: dict[str, Extractor],
) -> GroupDef:
    return GroupDef(
        name=name,
        class_uids=frozenset(class_uids),
        activity_ids=frozenset(activity_ids) if activity_ids is not None else None,
        log_names=frozenset({log_name}),
        fields=fields,
    )


SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
SYSTEM = "System"
TASK_SCHEDULER = "Microsoft-Windows-TaskScheduler/Operational"
PS_OPERATIONAL = "Microsoft-Windows-PowerShell/Operational"
PS_CLASSIC = "Windows PowerShell"


def _process_creation_fields() -> dict[str, Extractor]:
    return {
        "Image": typed("process", "file", "path"),
        "CommandLine": typed("process", "cmd_line"),
        "ParentImage": typed("process", "parent_process", "file", "path"),
        "ParentCommandLine": unmapped("ParentCommandLine"),
        "ParentUser": unmapped("ParentUser"),
        "User": actor_user,
        "LogonId": unmapped("LogonId"),
        "OriginalFileName": unmapped("OriginalFileName"),
        "Description": unmapped("Description"),
        "Product": unmapped("Product"),
        "Company": unmapped("Company"),
        "Hashes": unmapped("Hashes"),
        "IntegrityLevel": unmapped("IntegrityLevel"),
        "CurrentDirectory": unmapped("CurrentDirectory"),
        "FileVersion": unmapped("FileVersion"),
        **_standard(SYSMON, const("1")),
    }


def _granted_access_hex(event: dict[str, Any]) -> str | None:
    """Render ``actual_permissions`` in platform-native hex text.

    The schema types the mask as an integer, but Sigma rules match the
    Sysmon hex spelling (``contains '0x1038'``). Rendering back to hex
    restores exactly the logged form for masks parsed from hex; a mask
    logged in another base renders in hex too, which is what the rules
    compare. Mirrors :func:`hashes_sysmon_form`.
    """
    value = _dig(event, "actual_permissions")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return hex(value)
    return as_text(value)


def _process_access_fields() -> dict[str, Extractor]:
    return {
        "SourceImage": typed("actor", "process", "file", "path"),
        "TargetImage": typed("process", "file", "path"),
        "GrantedAccess": _granted_access_hex,
        "CallTrace": unmapped("CallTrace"),
        "SourceUser": unmapped("SourceUser"),
        **_standard(SYSMON, const("10")),
    }


def _image_load_fields() -> dict[str, Extractor]:
    # CommandLine has no source on image-load records: rules using it
    # are skipped with the field name (no entry here).
    return {
        "ImageLoaded": typed("module", "file", "path"),
        "Image": typed("actor", "process", "file", "path"),
        "Signed": unmapped("Signed"),
        "Signature": unmapped("Signature"),
        "SignatureStatus": unmapped("SignatureStatus"),
        "OriginalFileName": typed("module", "file", "internal_name"),
        "Description": typed("module", "file", "desc"),
        "Company": typed("module", "file", "company_name"),
        "Product": typed("module", "file", "product", "name"),
        "Hashes": hashes_sysmon_form,
        "RuleName": unmapped("RuleName"),
        **_standard(SYSMON, const("7")),
    }


def _network_fields() -> dict[str, Extractor]:
    # CommandLine and ParentImage have no source on Sysmon 3 records.
    return {
        "Image": typed("actor", "process", "file", "path"),
        "Initiated": unmapped("Initiated"),
        "DestinationIp": typed("dst_endpoint", "ip"),
        "DestinationHostname": unmapped("DestinationHostname"),
        "DestinationPort": typed("dst_endpoint", "port"),
        "Protocol": unmapped("Protocol"),
        "SourcePort": typed("src_endpoint", "port"),
        "SourceIp": typed("src_endpoint", "ip"),
        "User": actor_user,
        "SourceHostname": unmapped("SourceHostname"),
        "SourceIsIpv6": unmapped("SourceIsIpv6"),
        **_standard(SYSMON, const("3")),
    }


def _file_event_fields() -> dict[str, Extractor]:
    # CommandLine, ParentImage and ParentCommandLine have no source
    # on Sysmon 11 records.
    return {
        "TargetFilename": typed("file", "path"),
        "Image": typed("actor", "process", "file", "path"),
        **_standard(SYSMON, const("11")),
    }


def _registry_fields() -> dict[str, dict[str, Extractor]]:
    base_key = {
        "TargetObject": registry_target,
        "EventType": unmapped("EventType"),
        "Image": typed("actor", "process", "file", "path"),
        **_standard(SYSMON),
    }
    base_value = {
        "TargetObject": registry_target,
        "Details": typed("reg_value", "data"),
        "EventType": unmapped("EventType"),
        "Image": typed("actor", "process", "file", "path"),
        "User": actor_user,
        **_standard(SYSMON),
    }
    return {"key": base_key, "value": base_value}


def _ps_script_fields() -> dict[str, Extractor]:
    return {
        "ScriptBlockText": _script_content("4104"),
        "Path": unmapped("Path"),
        "EventID": _ps_event_id,
        **_standard(PS_OPERATIONAL),
    }


def _ps_module_fields() -> dict[str, Extractor]:
    return {
        "Payload": _script_content("4103"),
        "ContextInfo": unmapped("ContextInfo"),
        "EventID": _ps_event_id,
        **_standard(PS_OPERATIONAL),
    }


def _ps_classic_fields() -> dict[str, Extractor]:
    return {
        "Data": unmapped("Data"),
        **_standard(PS_CLASSIC, const("800")),
    }


def _subject_user(part: str) -> Extractor:
    """The Sigma ``SubjectUserName``/``SubjectDomainName`` on security rows.

    The 4697/4698 mappers consume the subject account into the typed
    actor (the installer), while 4624/4625 keep it in ``unmapped``
    (the actor there is the logon target). The source depends on the
    EventID, so the extractor branches on it; reading one side
    unconditionally would match installer names against logon-target
    rules or vice versa.
    """

    def read(event: dict[str, Any]) -> str | None:
        if (event.get("class_uid"), event.get("activity_id")) in (
            (201004, 1),
            (1006, 1),
        ):
            return as_text(_dig(event, "actor", "user", part))
        raw = event.get("unmapped")
        if not isinstance(raw, Mapping):
            return None
        return as_text(
            raw.get("SubjectUserName" if part == "name" else "SubjectDomainName")
        )

    return read


def _security_fields() -> dict[str, Extractor]:
    # Only the fields of the mapped EventIDs (4624, 4625, 4697,
    # 4698) are listed; every other security EventID routes the rule
    # to the skip pile before fields are consulted.
    columns: dict[str, Extractor] = {
        "TargetUserName": typed("actor", "user", "name"),
        "TargetUserSid": unmapped("TargetUserSid"),
        "TargetLogonId": unmapped("TargetLogonId"),
        "TargetOutboundUserName": unmapped("TargetOutboundUserName"),
        "TargetOutboundDomainName": unmapped("TargetOutboundDomainName"),
        "LogonType": unmapped("LogonType"),
        "LogonProcessName": unmapped("LogonProcessName"),
        "AuthenticationPackageName": unmapped("AuthenticationPackageName"),
        "WorkstationName": unmapped("WorkstationName"),
        "IpAddress": typed("src_endpoint", "ip"),
        "IpPort": typed("src_endpoint", "port"),
        "ProcessName": unmapped("ProcessName"),
        "LogonGuid": unmapped("LogonGuid"),
        "KeyLength": unmapped("KeyLength"),
        "LmPackageName": unmapped("LmPackageName"),
        "Status": unmapped("Status"),
        "SubStatus": unmapped("SubStatus"),
        "ImpersonationLevel": unmapped("ImpersonationLevel"),
        "ElevatedToken": unmapped("ElevatedToken"),
        "TransmittedServices": unmapped("TransmittedServices"),
        "VirtualAccount": unmapped("VirtualAccount"),
        "RestrictedAdminMode": unmapped("RestrictedAdminMode"),
        "TargetLinkedLogonId": unmapped("TargetLinkedLogonId"),
        "SamAccountName": unmapped("SamAccountName"),
        "SubjectUserName": _subject_user("name"),
        "SubjectDomainName": _subject_user("domain"),
        "SubjectUserSid": unmapped("SubjectUserSid"),
        "SubjectLogonId": unmapped("SubjectLogonId"),
        "TaskName": typed("job", "name"),
        "TaskContent": unmapped("TaskContent"),
        "TaskContentNew": unmapped("TaskContentNew"),
        "ClientProcessId": unmapped("ClientProcessId"),
        "ServiceName": typed("win_service", "name"),
        "ServiceFileName": typed("win_service", "cmd_line"),
        "ServiceStartType": unmapped("ServiceStartType"),
        "ServiceType": unmapped("ServiceType"),
        "ServiceAccount": typed("win_service", "service_start_name"),
        **_standard(SECURITY, event_id_for(SERVICE_EVENT_IDS)),
    }
    return columns


def _system_fields() -> dict[str, Extractor]:
    return {
        "ServiceName": typed("win_service", "name"),
        "ImagePath": typed("win_service", "cmd_line"),
        "ServiceType": unmapped("ServiceType"),
        "StartType": unmapped("StartType"),
        "AccountName": typed("actor", "user", "name"),
        **_standard(SYSTEM, event_id_for(SYSTEM_EVENT_IDS)),
    }


def _taskscheduler_fields() -> dict[str, Extractor]:
    return {
        "TaskName": typed("job", "name"),
        "User": actor_user,
        **_standard(TASK_SCHEDULER, event_id_for(TASK_EVENT_IDS)),
    }


_REGISTRY = _registry_fields()

GROUPS: dict[str, GroupDef] = {
    "process_creation": _group(
        "process_creation", {1007}, {1}, SYSMON, _process_creation_fields()
    ),
    "process_access": _group(
        "process_access", {1007}, {3}, SYSMON, _process_access_fields()
    ),
    "image_load": _group("image_load", {1005}, {1}, SYSMON, _image_load_fields()),
    "network_connection": _group(
        "network_connection", {4001}, {1}, SYSMON, _network_fields()
    ),
    "file_event": _group("file_event", {1001}, {1}, SYSMON, _file_event_fields()),
    "registry_add": _group(
        "registry_add",
        {201001, 201002},
        {1, 2},
        SYSMON,
        {**_REGISTRY["key"], **_REGISTRY["value"]},
    ),
    "registry_set": _group("registry_set", {201002}, {2}, SYSMON, _REGISTRY["value"]),
    "registry_delete": _group(
        "registry_delete",
        {201001, 201002},
        {4},
        SYSMON,
        {**_REGISTRY["key"], **_REGISTRY["value"]},
    ),
    "registry_event": _group(
        "registry_event",
        {201001, 201002},
        {1, 4, 5, 2},
        SYSMON,
        {
            **_REGISTRY["key"],
            **_REGISTRY["value"],
            "NewName": rename_new_name,
            "Details": typed("reg_value", "data"),
        },
    ),
    "ps_script": _group("ps_script", {1009}, {1}, PS_OPERATIONAL, _ps_script_fields()),
    "ps_module": _group("ps_module", {1009}, {1}, PS_OPERATIONAL, _ps_module_fields()),
    "ps_classic": _group("ps_classic", {1009}, {1}, PS_CLASSIC, _ps_classic_fields()),
    "security": _group(
        "security", {3002, 1006, 201004}, None, SECURITY, _security_fields()
    ),
    "system": _group("system", {201004}, {1}, SYSTEM, _system_fields()),
    "taskscheduler": _group(
        "taskscheduler", {1006}, {1}, TASK_SCHEDULER, _taskscheduler_fields()
    ),
}


#: Categories routing by name (everything except the service-routed
#: groups below).
CATEGORY_GROUPS = frozenset(
    {
        "process_creation",
        "process_access",
        "image_load",
        "network_connection",
        "file_event",
        "registry_add",
        "registry_set",
        "registry_delete",
        "registry_event",
        "ps_script",
        "ps_module",
        "ps_classic_start",
    }
)


def route_logsource(product: object, category: object, service: object) -> str | None:
    """Route a Sigma logsource triple to a group name, if any.

    Only ``windows``-product rules route anywhere; categories route
    by name (``ps_classic_start`` lands on the ``ps_classic``
    group); the ``powershell-classic`` service is the taxonomy alias
    of the same classic-pipeline group; ``security``, ``system`` and
    ``taskscheduler`` route by service. Anything else (other
    products, DNS, pipes, drivers, threat-hunting and
    emerging-threats products) returns None and the rule is counted
    per logsource and skipped.
    """
    if product != "windows":
        return None
    if category in CATEGORY_GROUPS:
        return "ps_classic" if category == "ps_classic_start" else str(category)
    if service == "powershell-classic":
        return "ps_classic"
    if service in ("security", "system", "taskscheduler"):
        return str(service)
    return None


def extract_row(
    event: dict[str, Any],
    group: GroupDef,
    *,
    need_fulltext: bool = True,
    raw_fallback: bool = True,
) -> dict[str, Any]:
    """Extract one DuckDB row for ``event`` under ``group``'s map.

    ``need_fulltext`` gates the raw-record column (keyword search);
    groups without keyword rules skip it to bound peak memory. When
    ``raw_fallback`` is set, a column the extractor left null is
    re-read from the raw record under the Sigma field name (the wire
    name): the normalizer nulls placeholders (``-``, empty, ``n/a``,
    ``unknown``) in typed slots, but Sigma compares the logged value,
    so the row carries it. ``raw_fallback=False`` keeps strict nulls
    (measurement only, for the old-vs-new match delta).
    """
    row: dict[str, Any] = {
        "uid": event.get("metadata", {}).get("uid")
        if isinstance(event.get("metadata"), dict)
        else None,
        "time": event.get("time"),
    }
    for name, read in group.fields.items():
        try:
            row[name] = read(event)
        except TypeError, AttributeError, ValueError:
            row[name] = None
    if raw_fallback and any(row[name] is None for name in group.fields):
        raw = _raw_record(event)
        fields = wire_fields(raw) if raw is not None else None
        if fields:
            for name in group.fields:
                if row[name] is None:
                    row[name] = _raw_text(fields, name)
    if need_fulltext:
        raw_data = event.get("raw_data")
        row[FULLTEXT_COLUMN] = raw_data if isinstance(raw_data, str) else None
    return row
