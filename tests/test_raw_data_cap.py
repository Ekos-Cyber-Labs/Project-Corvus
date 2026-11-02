"""Bounds on ``raw_data`` for both normalizers.

A hostile multi-megabyte command line must not grow one stored event
without bound: every string leaf inside ``raw_data`` truncates at the
documented cap with the original length kept in ``unmapped``. Windows
shapes come from ``tests/fixtures/windows_events.py``; Wazuh shapes
from ``tests/fixtures/wazuh/`` and ``tests/fixtures/linux/``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from corvus.normalize import wazuh
from corvus.normalize.wazuh import WAZUH_RAW_DATA_CAP
from corvus.normalize.windows import (
    WINDOWS_TEXT_CAP,
    UnmappedEvent,
    extract_json_parts,
    make_uid,
    normalize_event,
    sanitize_record,
)
from tests.fixtures import windows_events as fx

WAZUH_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
LINUX_FIXTURES = Path(__file__).parent / "fixtures" / "linux"


def _normalize_record(record: dict[str, Any]) -> Any:
    """Run a hand-made record through extraction plus normalization."""
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, 1
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid("raw-cap", record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _string_leaves(item)]
    if isinstance(value, (list, tuple)):
        return [leaf for item in value for leaf in _string_leaves(item)]
    return []


def test_caps_match_across_normalizers() -> None:
    """Both normalizers bound ``raw_data`` leaves at the same length."""
    assert WAZUH_RAW_DATA_CAP == WINDOWS_TEXT_CAP


def test_windows_huge_command_line_raw_data_capped() -> None:
    """A 5,000,000-character CommandLine stays a bounded event.

    Previously ``raw_data`` carried the whole value (about 5,000,229
    characters for this record); now every leaf truncates at
    ``WINDOWS_TEXT_CAP`` with the original length in
    ``unmapped["windows.raw_data_truncated"]``.
    """
    big = "A" * 5_000_000
    record = fx.flat_sysmon_process()
    record["CommandLine"] = f"powershell.exe -NoProfile -Command {big}"
    event = _normalize_record(record)
    assert event.process is not None
    assert event.process.cmd_line is not None
    assert len(event.process.cmd_line) == WINDOWS_TEXT_CAP
    assert event.unmapped.get("windows.cmdline_truncated") == len(record["CommandLine"])
    assert event.raw_data is not None
    assert len(event.raw_data) < 200_000
    raw = json.loads(event.raw_data)
    assert all(len(leaf) <= WINDOWS_TEXT_CAP for leaf in _string_leaves(raw))
    truncated = event.unmapped.get("windows.raw_data_truncated")
    assert isinstance(truncated, dict)
    assert truncated.get("$.CommandLine") == len(record["CommandLine"])


def test_windows_small_record_raw_data_unchanged() -> None:
    """Small records serialize exactly as before, with no truncation key."""
    record = fx.flat_sysmon_process()
    event = _normalize_record(record)
    assert "windows.raw_data_truncated" not in event.unmapped
    assert event.raw_data is not None
    assert json.loads(event.raw_data) == sanitize_record(record)


def _assert_typed_bound(event: Any, originals: dict[str, int]) -> None:
    """Every typed string fits the cap; every original length is kept.

    ``entity_keys`` are excluded here and pinned per test: they are
    derived by joining already-capped slots (``domain`` + ``name``),
    so a two-field identity is bounded by just under twice the cap,
    while single-field keys fit the cap itself.
    """
    for leaf in _string_leaves(
        event.model_dump(exclude={"raw_data", "unmapped", "entity_keys"})
    ):
        assert len(leaf) <= WINDOWS_TEXT_CAP
    for key, length in originals.items():
        assert event.unmapped.get(key) == length, key


def test_windows_huge_image_user_parent_image_capped() -> None:
    """A 5,000,000-character Image, User and ParentImage stay bounded.

    Previously the values landed verbatim in ``process.name``,
    ``process.file.path``, ``actor.user.name`` and (via canonicalization)
    ``entity_keys.user``; now each typed slot truncates at
    ``WINDOWS_TEXT_CAP`` with the original length in ``unmapped``.
    """
    image = "C:\\Windows\\" + "I" * 5_000_000 + ".exe"
    user = "EXAMPLE\\" + "U" * 5_000_000
    parent = "C:\\Windows\\" + "P" * 5_000_000 + ".exe"
    record = fx.flat_sysmon_process()
    record["Image"] = image
    record["User"] = user
    record["ParentImage"] = parent
    event = _normalize_record(record)
    assert event.process is not None
    assert event.process.name is not None
    assert len(event.process.name) <= WINDOWS_TEXT_CAP
    assert event.process.file is not None
    assert len(event.process.file.path or "") <= WINDOWS_TEXT_CAP
    assert event.process.parent_process is not None
    assert event.process.parent_process.file is not None
    assert len(event.process.parent_process.file.path or "") <= WINDOWS_TEXT_CAP
    assert event.actor is not None and event.actor.user is not None
    assert len(event.actor.user.name or "") <= WINDOWS_TEXT_CAP
    assert len(event.entity_keys.user or "") <= WINDOWS_TEXT_CAP
    assert (event.actor.user.name or "") != user
    _assert_typed_bound(
        event,
        {
            "windows.image_truncated": len(image),
            "windows.user_truncated": len(user),
            "windows.parent_image_truncated": len(parent),
        },
    )
    assert event.raw_data is not None
    assert all(
        len(leaf) <= WINDOWS_TEXT_CAP
        for leaf in _string_leaves(json.loads(event.raw_data))
    )


def test_windows_huge_target_filename_capped() -> None:
    """A 5,000,000-character TargetFilename stays a bounded event."""
    target = "C:\\Temp\\" + "F" * 5_000_000 + ".bin"
    record = fx.flat_sysmon_file()
    record["TargetFilename"] = target
    event = _normalize_record(record)
    assert event.file is not None
    assert len(event.file.path or "") <= WINDOWS_TEXT_CAP
    assert (event.file.path or "") != target
    _assert_typed_bound(event, {"windows.target_filename_truncated": len(target)})


def test_windows_huge_registry_service_computer_capped() -> None:
    """Registry paths, service names, hashes and the host stay bounded."""
    target = "HKLM\\Software\\" + "K" * 5_000_000 + "\\Value"
    record = fx.flat_sysmon_registry_value()
    record["TargetObject"] = target
    event = _normalize_record(record)
    assert event.reg_value is not None
    assert len(event.reg_value.path or "") <= WINDOWS_TEXT_CAP
    assert len(event.reg_value.name or "") <= WINDOWS_TEXT_CAP
    assert (event.reg_value.path or "") != target
    _assert_typed_bound(event, {"windows.registry_target_truncated": len(target)})

    record = fx.flat_sysmon_module()
    record["Hashes"] = "SHA256=" + "D" * 5_000_000
    event = _normalize_record(record)
    assert event.module is not None and event.module.file is not None
    assert event.module.file.hashes is not None
    for fingerprint in event.module.file.hashes:
        assert len(fingerprint.value or "") <= WINDOWS_TEXT_CAP
    _assert_typed_bound(event, {"windows.hash_truncated": 5_000_000})

    service = "Svc" + "S" * 5_000_000
    record = fx.flat_security_service()
    record["ServiceName"] = service
    record["ServiceFileName"] = "C:\\Svc\\" + "C" * 5_000_000 + ".exe"
    event = _normalize_record(record)
    assert event.win_service is not None
    assert len(event.win_service.name or "") <= WINDOWS_TEXT_CAP
    assert len(event.win_service.cmd_line or "") <= WINDOWS_TEXT_CAP
    _assert_typed_bound(
        event,
        {
            "windows.service_name_truncated": len(service),
            "windows.service_cmdline_truncated": len(record["ServiceFileName"]),
        },
    )

    record = fx.flat_security_logon(success=True)
    record["TargetUserName"] = "L" * 5_000_000
    record["Hostname"] = "H" * 5_000_000 + ".example.com"
    event = _normalize_record(record)
    assert event.user is not None
    assert len(event.user.name or "") <= WINDOWS_TEXT_CAP
    assert event.device is not None
    assert len(event.device.hostname or "") <= WINDOWS_TEXT_CAP
    # Two separately capped fields join into one key ("EXAMPLE" + name).
    assert len(event.entity_keys.user or "") < 2 * WINDOWS_TEXT_CAP
    assert len(event.entity_keys.host or "") <= WINDOWS_TEXT_CAP
    _assert_typed_bound(
        event,
        {
            "windows.user_truncated": 5_000_000,
            "windows.computer_truncated": len(record["Hostname"]),
        },
    )


def _load_wazuh(name: str) -> dict:
    return json.loads((WAZUH_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def test_wazuh_alert_huge_command_raw_data_capped() -> None:
    """A hostile sudo command stays a bounded finding and event."""
    hit = _load_wazuh("sudo")
    big = "sudo ls " + "B" * 200_000
    hit["_source"]["command"] = big
    finding, event, key = wazuh.map_alert(hit)
    assert key is None
    assert event is not None
    for record in (finding, event):
        assert record.raw_data is not None
        assert len(record.raw_data) < 200_000
        raw = json.loads(record.raw_data)
        assert all(len(leaf) <= WAZUH_RAW_DATA_CAP for leaf in _string_leaves(raw))
        truncated = record.unmapped.get("wazuh.raw_data_truncated")
        assert isinstance(truncated, dict)
        assert truncated.get("$.command") == len(big)
    # The typed command is capped like every other typed Wazuh slot.
    assert event.process is not None
    assert event.process.cmd_line == big[:WAZUH_RAW_DATA_CAP]
    assert event.unmapped.get("wazuh.command_truncated") == len(big)


def test_wazuh_small_alert_raw_data_unchanged() -> None:
    """Small alerts serialize exactly as before, with no truncation key."""
    finding, event, key = wazuh.map_alert(_load_wazuh("sudo"))
    assert key is None and event is not None
    for record in (finding, event):
        assert "wazuh.raw_data_truncated" not in record.unmapped
    source = _load_wazuh("sudo")["_source"]
    assert json.loads(event.raw_data or "{}") == source
    assert json.loads(finding.raw_data or "{}") == source


def test_wazuh_archive_huge_blob_raw_data_capped() -> None:
    """A hostile archive document stays a bounded event."""
    doc = json.loads((LINUX_FIXTURES / "auth.json").read_text(encoding="utf-8"))
    doc["extra_blob"] = "X" * 300_000
    finding, event, key, dedupe = wazuh.map_linux_doc(doc)
    assert event is not None
    assert event.raw_data is not None
    assert len(event.raw_data) < 200_000
    raw = json.loads(event.raw_data)
    assert all(len(leaf) <= WAZUH_RAW_DATA_CAP for leaf in _string_leaves(raw))
    truncated = event.unmapped.get("wazuh.raw_data_truncated")
    assert isinstance(truncated, dict)
    assert truncated.get("$.extra_blob") == 300_000
    if finding is not None:
        assert finding.raw_data is not None
        assert len(finding.raw_data) < 200_000
        assert json.loads(finding.raw_data).get("extra_blob") is not None
        assert len(json.loads(finding.raw_data)["extra_blob"]) <= WAZUH_RAW_DATA_CAP


#: Hostile value fed into one typed field per matrix case.
BIG = "X" * 5_000_000


def _process_file(event: Any) -> str | None:
    if event.process is None or event.process.file is None:
        return None
    return event.process.file.path


def _process_parent_file(event: Any) -> str | None:
    parent = event.process.parent_process if event.process is not None else None
    if parent is None or parent.file is None:
        return None
    return parent.file.path


def _actor_name(event: Any) -> str | None:
    if event.actor is None or event.actor.user is None:
        return None
    return event.actor.user.name


def _actor_domain(event: Any) -> str | None:
    if event.actor is None or event.actor.user is None:
        return None
    return event.actor.user.domain


def _actor_process_file(event: Any) -> str | None:
    proc = event.actor.process if event.actor is not None else None
    if proc is None or proc.file is None:
        return None
    return proc.file.path


def _module_file(event: Any) -> Any:
    if event.module is None:
        return None
    return event.module.file


def _without_user(record: dict[str, Any]) -> dict[str, Any]:
    """Copy a record with the ``User`` key removed (AccountName branch)."""
    return {key: value for key, value in record.items() if key != "User"}


def _ps_account(record: dict[str, Any]) -> dict[str, Any]:
    """Copy a 4104 record onto the ``AccountName``/``Domain`` branch."""
    swapped = _without_user(record)
    swapped["AccountName"] = "jdoe"
    swapped["Domain"] = "EXAMPLE"
    return swapped


#: (case id, record factory, typed field, typed-slot getter, unmapped key).
#: One case per typed Windows slot, so reverting any single cap call
#: fails its case: the slot keeps the full value and the length key is
#: missing. ``Hostname`` exercises the computer cap in
#: :func:`normalize_event`; ``Hashes`` the digest cap in the hash
#: parser; service start/type the 99-Other caption caps.
_CAP_CASES: list[
    tuple[str, Callable[[], dict[str, Any]], str, Callable[[Any], str | None], str]
] = [
    (
        "ev1-Image",
        fx.flat_sysmon_process,
        "Image",
        _process_file,
        "windows.image_truncated",
    ),
    (
        "ev1-ParentImage",
        fx.flat_sysmon_process,
        "ParentImage",
        _process_parent_file,
        "windows.parent_image_truncated",
    ),
    ("ev1-User", fx.flat_sysmon_process, "User", _actor_name, "windows.user_truncated"),
    (
        "ev1-Hostname",
        fx.flat_sysmon_process,
        "Hostname",
        lambda event: event.device.hostname if event.device else None,
        "windows.computer_truncated",
    ),
    (
        "ev3-Image",
        fx.flat_sysmon_network,
        "Image",
        _actor_process_file,
        "windows.image_truncated",
    ),
    ("ev3-User", fx.flat_sysmon_network, "User", _actor_name, "windows.user_truncated"),
    (
        "ev3-SourceIp",
        fx.flat_sysmon_network,
        "SourceIp",
        lambda event: event.src_endpoint.ip if event.src_endpoint else None,
        "windows.src_ip_truncated",
    ),
    (
        "ev3-DestinationIp",
        fx.flat_sysmon_network,
        "DestinationIp",
        lambda event: event.dst_endpoint.ip if event.dst_endpoint else None,
        "windows.dst_ip_truncated",
    ),
    (
        "ev7-ImageLoaded",
        fx.flat_sysmon_module,
        "ImageLoaded",
        lambda event: _module_file(event).path if _module_file(event) else None,
        "windows.image_loaded_truncated",
    ),
    (
        "ev7-Image",
        fx.flat_sysmon_module,
        "Image",
        _actor_process_file,
        "windows.image_truncated",
    ),
    ("ev7-User", fx.flat_sysmon_module, "User", _actor_name, "windows.user_truncated"),
    (
        "ev7-AccountName",
        fx.flat_sysmon_module,
        "AccountName",
        _actor_name,
        "windows.user_truncated",
    ),
    (
        "ev7-Domain",
        fx.flat_sysmon_module,
        "Domain",
        _actor_domain,
        "windows.domain_truncated",
    ),
    (
        "ev7-Description",
        fx.flat_sysmon_module,
        "Description",
        lambda event: _module_file(event).desc if _module_file(event) else None,
        "windows.description_truncated",
    ),
    (
        "ev7-Company",
        fx.flat_sysmon_module,
        "Company",
        lambda event: _module_file(event).company_name if _module_file(event) else None,
        "windows.company_truncated",
    ),
    (
        "ev7-Product",
        fx.flat_sysmon_module,
        "Product",
        lambda event: (
            _module_file(event).product.name
            if _module_file(event) and _module_file(event).product
            else None
        ),
        "windows.product_truncated",
    ),
    (
        "ev7-OriginalFileName",
        fx.flat_sysmon_module,
        "OriginalFileName",
        lambda event: (
            _module_file(event).internal_name if _module_file(event) else None
        ),
        "windows.original_filename_truncated",
    ),
    (
        "ev7-Hashes",
        fx.flat_sysmon_module,
        "Hashes",
        lambda event: (
            _module_file(event).hashes[0].value
            if _module_file(event) and _module_file(event).hashes
            else None
        ),
        "windows.hash_truncated",
    ),
    (
        "ev11-TargetFilename",
        fx.flat_sysmon_file,
        "TargetFilename",
        lambda event: event.file.path if event.file else None,
        "windows.target_filename_truncated",
    ),
    (
        "ev11-Image",
        fx.flat_sysmon_file,
        "Image",
        _actor_process_file,
        "windows.image_truncated",
    ),
    ("ev11-User", fx.flat_sysmon_file, "User", _actor_name, "windows.user_truncated"),
    (
        "reg12-TargetObject",
        fx.flat_sysmon_registry_key,
        "TargetObject",
        lambda event: event.reg_key.path if event.reg_key else None,
        "windows.registry_target_truncated",
    ),
    (
        "reg12-Image",
        fx.flat_sysmon_registry_key,
        "Image",
        _actor_process_file,
        "windows.image_truncated",
    ),
    (
        "reg12-AccountName",
        fx.flat_sysmon_registry_key,
        "AccountName",
        _actor_name,
        "windows.user_truncated",
    ),
    (
        "reg12-Domain",
        fx.flat_sysmon_registry_key,
        "Domain",
        _actor_domain,
        "windows.domain_truncated",
    ),
    (
        "reg13-TargetObject",
        fx.flat_sysmon_registry_value,
        "TargetObject",
        lambda event: event.reg_value.path if event.reg_value else None,
        "windows.registry_target_truncated",
    ),
    (
        "reg13-Image",
        fx.flat_sysmon_registry_value,
        "Image",
        _actor_process_file,
        "windows.image_truncated",
    ),
    (
        "reg14-TargetObject",
        fx.flat_sysmon_registry_rename,
        "TargetObject",
        lambda event: event.reg_key.path if event.reg_key else None,
        "windows.registry_target_truncated",
    ),
    (
        "reg14-NewName",
        fx.flat_sysmon_registry_rename,
        "NewName",
        lambda event: event.reg_key.path if event.reg_key else None,
        "windows.registry_new_name_truncated",
    ),
    (
        "reg14-Image",
        fx.flat_sysmon_registry_rename,
        "Image",
        _actor_process_file,
        "windows.image_truncated",
    ),
    (
        "logon4624-TargetUserName",
        lambda: fx.flat_security_logon(success=True),
        "TargetUserName",
        lambda event: event.user.name if event.user else None,
        "windows.user_truncated",
    ),
    (
        "logon4624-TargetDomainName",
        lambda: fx.flat_security_logon(success=True),
        "TargetDomainName",
        lambda event: event.user.domain if event.user else None,
        "windows.domain_truncated",
    ),
    (
        "logon4625-TargetUserName",
        lambda: fx.flat_security_logon(success=False),
        "TargetUserName",
        lambda event: event.user.name if event.user else None,
        "windows.user_truncated",
    ),
    (
        "svc4697-ServiceName",
        fx.flat_security_service,
        "ServiceName",
        lambda event: event.win_service.name if event.win_service else None,
        "windows.service_name_truncated",
    ),
    (
        "svc4697-ServiceFileName",
        fx.flat_security_service,
        "ServiceFileName",
        lambda event: event.win_service.cmd_line if event.win_service else None,
        "windows.service_cmdline_truncated",
    ),
    (
        "svc4697-ServiceAccount",
        fx.flat_security_service,
        "ServiceAccount",
        lambda event: (
            event.win_service.service_start_name if event.win_service else None
        ),
        "windows.service_account_truncated",
    ),
    (
        "svc4697-SubjectUserName",
        fx.flat_security_service,
        "SubjectUserName",
        _actor_name,
        "windows.user_truncated",
    ),
    (
        "svc4697-SubjectDomainName",
        fx.flat_security_service,
        "SubjectDomainName",
        _actor_domain,
        "windows.domain_truncated",
    ),
    (
        "svc4697-ServiceStartType",
        fx.flat_security_service,
        "ServiceStartType",
        lambda event: (
            event.win_service.service_start_type if event.win_service else None
        ),
        "windows.service_start_type_truncated",
    ),
    (
        "svc4697-ServiceType",
        fx.flat_security_service,
        "ServiceType",
        lambda event: event.win_service.service_type if event.win_service else None,
        "windows.service_type_truncated",
    ),
    (
        "svc7045-ServiceName",
        fx.flat_service_install,
        "ServiceName",
        lambda event: event.win_service.name if event.win_service else None,
        "windows.service_name_truncated",
    ),
    (
        "svc7045-ImagePath",
        fx.flat_service_install,
        "ImagePath",
        lambda event: event.win_service.cmd_line if event.win_service else None,
        "windows.service_cmdline_truncated",
    ),
    (
        "svc7045-AccountName",
        fx.flat_service_install,
        "AccountName",
        _actor_name,
        "windows.user_truncated",
    ),
    (
        "svc7045-Domain",
        fx.flat_service_install,
        "Domain",
        _actor_domain,
        "windows.domain_truncated",
    ),
    (
        "ps4104-User",
        fx.flat_powershell_script,
        "User",
        _actor_name,
        "windows.user_truncated",
    ),
    (
        "ps4104-AccountName",
        lambda: _ps_account(fx.flat_powershell_script()),
        "AccountName",
        _actor_name,
        "windows.user_truncated",
    ),
    (
        "ps4104-Domain",
        lambda: _ps_account(fx.flat_powershell_script()),
        "Domain",
        _actor_domain,
        "windows.domain_truncated",
    ),
    (
        "ps4104-ScriptBlockId",
        fx.flat_powershell_script,
        "ScriptBlockId",
        lambda event: event.script.uid if event.script else None,
        "windows.script_uid_truncated",
    ),
]


@pytest.mark.parametrize(
    "case_id,make_record,field,get_typed,cap_key",
    _CAP_CASES,
    ids=[case[0] for case in _CAP_CASES],
)
def test_typed_cap(
    case_id: str,
    make_record: Callable[[], dict[str, Any]],
    field: str,
    get_typed: Callable[[Any], str | None],
    cap_key: str,
) -> None:
    """Every typed Windows slot truncates a hostile value at the cap.

    One case per typed slot: a 5,000,000-character value lands
    truncated at ``WINDOWS_TEXT_CAP`` with its original length
    recorded in ``unmapped``. Reverting any single cap call to an
    uncapped read fails its case (the slot keeps the full value and
    the length key is missing).
    """
    record = make_record()
    # The hash parser needs one ``ALG=digest`` pair to emit a slot, and
    # records the digest length (without the ``ALG=`` prefix).
    value = BIG if field != "Hashes" else "SHA256=" + "D" * (len(BIG) - 7)
    expected = len(value) if field != "Hashes" else len(value) - len("SHA256=")
    record[field] = value
    event = _normalize_record(record)
    typed = get_typed(event)
    assert typed is not None, f"{case_id}: typed slot is missing"
    assert len(typed) <= WINDOWS_TEXT_CAP, f"{case_id}: len={len(typed)}"
    assert typed != value, f"{case_id}: full value kept"
    assert event.unmapped.get(cap_key) == expected, f"{case_id}: {cap_key} missing"


#: Layouts with no mapper: the record stays counted as unmapped.
_UNMAPPED_CASES: list[tuple[str, dict[str, Any]]] = [
    (
        "sysmon-15",
        {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 15,
            "EventIdx": 901,
            "Hostname": "web01.example.com",
            "TimeCreated": fx.SYS_UTC,
            "Image": BIG,
        },
    ),
    (
        "sysmon-22",
        {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 22,
            "EventIdx": 902,
            "Hostname": "web01.example.com",
            "TimeCreated": fx.SYS_UTC,
            "QueryName": BIG,
        },
    ),
    ("security-4688", dict(fx.flat_unmapped(event_id=4688), NewProcessName=BIG)),
    (
        "security-4720",
        {
            "Channel": "Security",
            "EventID": 4720,
            "EventIdx": 904,
            "Hostname": "web01.example.com",
            "TimeCreated": fx.SYS_UTC,
            "TargetUserName": BIG,
        },
    ),
    (
        "security-4732",
        {
            "Channel": "Security",
            "EventID": 4732,
            "EventIdx": 905,
            "Hostname": "web01.example.com",
            "TimeCreated": fx.SYS_UTC,
            "MemberName": BIG,
        },
    ),
]


@pytest.mark.parametrize(
    "case_id,record",
    [(case_id, record) for case_id, record in _UNMAPPED_CASES],
    ids=[case_id for case_id, _ in _UNMAPPED_CASES],
)
def test_unmapped_layouts_stay_unmapped(case_id: str, record: dict[str, Any]) -> None:
    """Layouts with no mapper stay counted as unmapped, never half-typed."""
    with pytest.raises(UnmappedEvent):
        _normalize_record(record)


#: Exact-boundary cases: 65,536 is kept intact, 65,537 is cut.
_BOUNDARY_CASES: list[
    tuple[str, Callable[[], dict[str, Any]], str, Callable[[Any], str | None], str]
] = [
    (
        "ev1-Image",
        fx.flat_sysmon_process,
        "Image",
        _process_file,
        "windows.image_truncated",
    ),
    (
        "ev11-TargetFilename",
        fx.flat_sysmon_file,
        "TargetFilename",
        lambda event: event.file.path if event.file else None,
        "windows.target_filename_truncated",
    ),
    (
        "reg13-TargetObject",
        fx.flat_sysmon_registry_value,
        "TargetObject",
        lambda event: event.reg_value.path if event.reg_value else None,
        "windows.registry_target_truncated",
    ),
    (
        "svc4697-ServiceName",
        fx.flat_security_service,
        "ServiceName",
        lambda event: event.win_service.name if event.win_service else None,
        "windows.service_name_truncated",
    ),
    (
        "logon4624-TargetUserName",
        lambda: fx.flat_security_logon(success=True),
        "TargetUserName",
        lambda event: event.user.name if event.user else None,
        "windows.user_truncated",
    ),
]


@pytest.mark.parametrize(
    "case_id,make_record,field,get_typed,cap_key",
    _BOUNDARY_CASES,
    ids=[case[0] for case in _BOUNDARY_CASES],
)
def test_exact_cap_boundary(
    case_id: str,
    make_record: Callable[[], dict[str, Any]],
    field: str,
    get_typed: Callable[[Any], str | None],
    cap_key: str,
) -> None:
    """65,536 characters pass through intact; 65,537 truncates."""
    record = make_record()
    record[field] = "X" * WINDOWS_TEXT_CAP
    event = _normalize_record(record)
    assert get_typed(event) == "X" * WINDOWS_TEXT_CAP, case_id
    assert cap_key not in event.unmapped, case_id
    record = make_record()
    record[field] = "X" * (WINDOWS_TEXT_CAP + 1)
    event = _normalize_record(record)
    typed = get_typed(event)
    assert typed == "X" * WINDOWS_TEXT_CAP, case_id
    assert event.unmapped.get(cap_key) == WINDOWS_TEXT_CAP + 1, case_id
