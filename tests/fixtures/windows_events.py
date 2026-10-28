"""Hand-written Windows fixtures for the normalizer tests.

Every record is invented: RFC 5737 documentation addresses, ``example.com``
hosts, fake users. Shapes mirror the two replay formats (nested ``.evtx``
JSON and flat OTRF JSON-lines) without copying any dataset content.
"""

from typing import Any

SYS_UTC = "2024-05-02T14:03:00.000Z"
SYS_UTCTIME = "2024-05-02 14:03:00.000"

#: 2024-05-02T14:03:00Z as UTC epoch milliseconds.
SYS_MS = 1714658580000


def flat_sysmon_process() -> dict[str, Any]:
    """Flat Sysmon event 1 (process creation)."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "EventIdx": 101,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -Command Get-Process",
        "User": "EXAMPLE\\jdoe",
        "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
        "ParentProcessId": 1234,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "C:\\Windows\\explorer.exe",
    }


def flat_sysmon_network() -> dict[str, Any]:
    """Flat Sysmon event 3 (network connection)."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 3,
        "EventIdx": 102,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "User": "EXAMPLE\\jdoe",
        "Protocol": "tcp",
        "SourceIp": "192.0.2.10",
        "SourcePort": 52310,
        "DestinationIp": "203.0.113.7",
        "DestinationPort": 443,
        "DestinationHostname": "download.example.com",
    }


def flat_sysmon_file() -> dict[str, Any]:
    """Flat Sysmon event 11 (file creation)."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 11,
        "EventIdx": 103,
        "Hostname": "db01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "User": "EXAMPLE\\svc-backup",
        "TargetFilename": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\dropper.bin",
    }


def flat_security_logon(*, success: bool) -> dict[str, Any]:
    """Flat Security 4624 (success) / 4625 (failure) logon."""
    return {
        "Channel": "Security",
        "EventID": 4624 if success else 4625,
        "EventIdx": 104 if success else 105,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "TargetUserName": "jdoe",
        "TargetDomainName": "EXAMPLE",
        "LogonType": 3,
        "IpAddress": "198.51.100.23",
        "IpPort": 4444,
        "WorkstationName": "client01.example.com",
    }


def flat_security_task() -> dict[str, Any]:
    """Flat Security 4698 (scheduled task created)."""
    return {
        "Channel": "Security",
        "EventID": 4698,
        "EventIdx": 106,
        "Hostname": "db01.example.com",
        "TimeCreated": SYS_UTC,
        "SubjectUserName": "jdoe",
        "SubjectDomainName": "EXAMPLE",
        "TaskName": "\\Example\\NightlySync",
        "TaskContentNew": "<Task><Actions><Exec><Command>sync</Command></Exec>",
    }


def flat_taskscheduler_106() -> dict[str, Any]:
    """Flat Microsoft-Windows-TaskScheduler/Operational 106 (task registered)."""
    return {
        "Channel": "Microsoft-Windows-TaskScheduler/Operational",
        "EventID": 106,
        "EventIdx": 107,
        "Hostname": "db01.example.com",
        "TimeCreated": SYS_UTC,
        "TaskName": "\\Example\\NightlySync",
        "User": "EXAMPLE\\svc-backup",
        "UserData": "Task registered (invented detail).",
    }


def flat_unmapped(*, event_id: int = 4688, channel: str = "Security") -> dict[str, Any]:
    """Flat record with no mapping (process creation is out of scope)."""
    return {
        "Channel": channel,
        "EventID": event_id,
        "EventIdx": 108,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
    }


def flat_minimal_process() -> dict[str, Any]:
    """Flat Sysmon event 1 with every optional field missing."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "EventIdx": 109,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
    }


def flat_unicode_process() -> dict[str, Any]:
    """Flat Sysmon event 1 with non-ASCII text in the command line."""
    record = flat_sysmon_process()
    record["EventIdx"] = 110
    record["CommandLine"] = "powershell.exe -Command Write-Host 'héllo wörld 数据 🎯'"
    record["Image"] = "C:\\Temp\\données\\outilβ.exe"
    return record


def evtx_sysmon_process() -> dict[str, Any]:
    """Nested ``.evtx`` JSON shape of a Sysmon event 1."""
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "web01.example.com",
                "EventRecordID": 201,
                "TimeCreated": {"#attributes": {"SystemTime": SYS_UTC}},
            },
            "EventData": {
                "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
                "ProcessId": 4321,
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "User": "EXAMPLE\\jdoe",
                "ParentProcessId": 1234,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "UtcTime": SYS_UTCTIME,
            },
        }
    }


def flat_sysmon_access() -> dict[str, Any]:
    """Flat Sysmon event 10 (one process opening a handle to another)."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 10,
        "EventIdx": 112,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "ProcessGuid": "{aaaaaaaa-1111-2222-3333-444444444444}",
        "ProcessId": 888,
        "Image": "C:\\Windows\\System32\\lsass.exe",
        "User": "EXAMPLE\\jdoe",
        "TargetProcessGUID": "{aaaaaaaa-1111-2222-3333-444444444444}",
        "TargetProcessId": 888,
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "SourceProcessGUID": "{bbbbbbbb-5555-6666-7777-888888888888}",
        "SourceProcessId": 4321,
        "SourceThreadId": 5678,
        "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "GrantedAccess": "0x1010",
        "CallTrace": (
            "C:\\Windows\\SYSTEM32\\ntdll.dll+9e0c0|"
            "C:\\Windows\\System32\\KERNELBASE.dll+2a1b3"
        ),
    }


def flat_powershell_script() -> dict[str, Any]:
    """Flat PowerShell Operational 4104 (script block logging, one message)."""
    return {
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "EventID": 4104,
        "EventIdx": 113,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "User": "EXAMPLE\\jdoe",
        "ScriptBlockText": "Get-Process | Where-Object { $_.CPU -gt 10 }",
        "ScriptBlockId": "{cccccccc-9999-aaaa-bbbb-cccccccccccc}",
        "MessageNumber": 1,
        "MessageTotal": 1,
    }


def flat_powershell_script_split() -> list[dict[str, Any]]:
    """One 4104 script block split across three messages (hand-made parts)."""
    block = "{dddddddd-0000-1111-2222-333333333333}"
    parts = (
        "$data = Get-Process |",
        "Where-Object { $_.CPU -gt 10 } |",
        "Select-Object Name, CPU",
    )
    records = []
    for number, text in enumerate(parts, start=1):
        record = flat_powershell_script()
        record["EventIdx"] = 113 + number
        record["ScriptBlockId"] = block
        record["ScriptBlockText"] = text
        record["MessageNumber"] = number
        record["MessageTotal"] = 3
        records.append(record)
    return records


def flat_powershell_module() -> dict[str, Any]:
    """Flat PowerShell Operational 4103 (module logging, NXLog layout)."""
    return {
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "EventID": 4103,
        "EventIdx": 114,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "AccountName": "jdoe",
        "Domain": "EXAMPLE",
        "Payload": 'CommandInvocation(Get-Process): "Get-Process"',
        "ContextInfo": "Host Name = ConsoleHost (invented context).",
    }


def flat_windows_powershell_pipeline() -> dict[str, Any]:
    """Flat Windows PowerShell 800 (pipeline execution details)."""
    return {
        "Channel": "Windows PowerShell",
        "EventID": 800,
        "EventIdx": 115,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "Message": "Pipeline execution details for command line: Get-Process",
    }


def flat_windows_powershell_provider() -> dict[str, Any]:
    """Flat Windows PowerShell 600 (provider lifecycle, no script content)."""
    return {
        "Channel": "Windows PowerShell",
        "EventID": 600,
        "EventIdx": 116,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "Message": 'Provider "Registry" is Started (invented text).',
    }


def flat_service_install(*, channel: str = "System") -> dict[str, Any]:
    """Flat service-installed record (System 7045 / Security 4697 shape)."""
    event_id = 7045 if channel == "System" else 4697
    return {
        "Channel": channel,
        "EventID": event_id,
        "EventIdx": 117,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "ServiceName": "ExampleSupport",
        "ImagePath": "C:\\Windows\\System32\\examplesup.exe",
        "StartType": "auto start",
        "ServiceType": "user mode service",
        "AccountName": "jdoe",
        "Domain": "EXAMPLE",
        "UserID": "S-1-5-21-1111-2222-3333-1001",
    }


def flat_security_service() -> dict[str, Any]:
    """Flat Security 4697 (a service was installed)."""
    return {
        "Channel": "Security",
        "EventID": 4697,
        "EventIdx": 118,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "ServiceName": "ExampleSupport",
        "ServiceFileName": "C:\\Windows\\System32\\examplesup.exe",
        "ServiceStartType": "2",
        "ServiceType": "0x10",
        "ServiceAccount": "LocalSystem",
        "SubjectUserName": "jdoe",
        "SubjectDomainName": "EXAMPLE",
    }


def _nxlog_message(*, operation: str, target: str) -> str:
    """NXLog-rendered record text: the op lives on the EventType line.

    Flat NXLog Sysmon records carry ``EventType: INFO`` (the severity)
    in the field; the real operation is only on this ``Message`` line.
    """
    return (
        "Registry object added or deleted:\r\n"
        "RuleName: -\r\n"
        f"EventType: {operation}\r\n"
        f"UtcTime: {SYS_UTCTIME}\r\n"
        "ProcessGuid: {11111111-2222-3333-4444-555555555555}\r\n"
        "ProcessId: 4321\r\n"
        "Image: C:\\Windows\\regedit.exe\r\n"
        f"TargetObject: {target}\r\n"
    )


def flat_sysmon_registry_key(*, event_type: str = "CreateKey") -> dict[str, Any]:
    """Flat Sysmon event 12 (registry key created or deleted).

    Mirrors the real flat layout: ``EventType`` is the ``INFO``
    severity and the operation is the ``Message`` ``EventType:`` line.
    """
    target = "HKLM\\SOFTWARE\\ExampleCorp\\ExampleApp"
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 12,
        "EventIdx": 119,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "EventType": "INFO",
        "TargetObject": target,
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\regedit.exe",
        "UserID": "S-1-5-18",
        "AccountName": "SYSTEM",
        "Domain": "NT AUTHORITY",
        "RuleName": "-",
        "Message": _nxlog_message(operation=event_type, target=target),
    }


def flat_sysmon_registry_value() -> dict[str, Any]:
    """Flat Sysmon event 13 (registry value set on a Run key).

    Mirrors the real flat layout: ``EventType`` is the ``INFO``
    severity and ``SetValue`` is the ``Message`` ``EventType:`` line.
    """
    target = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ExampleApp"
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 13,
        "EventIdx": 120,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "EventType": "INFO",
        "TargetObject": target,
        "Details": "C:\\Tools\\example.exe",
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\regedit.exe",
        "UserID": "S-1-5-18",
        "AccountName": "SYSTEM",
        "Domain": "NT AUTHORITY",
        "RuleName": "-",
        "Message": _nxlog_message(operation="SetValue", target=target),
    }


def flat_sysmon_module() -> dict[str, Any]:
    """Flat Sysmon event 7 (image loaded, NXLog layout).

    Mirrors the real flat record: ``EventType`` is the ``INFO``
    severity, the account arrives as ``AccountName``/``Domain``
    (no ``User`` key), ``ProcessId`` is a string, and ``Hashes`` is
    the comma-separated ``ALG=value`` list. ``Message`` repeats the
    payload as rendered text.
    """
    loaded = "C:\\Windows\\System32\\wmidcom.dll"
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 7,
        "EventIdx": 122,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "EventType": "INFO",
        "ImageLoaded": loaded,
        "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)",
        "Description": "WMI",
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": "wmidcom.dll",
        "Hashes": (
            "SHA1=4C7308C2A323D850C3E5DCB88A32A1C7DF9CBE4F,"
            "MD5=A9BC5F3E3C6406C3C5ABE804FBF7BC76,"
            "SHA256=A0177FD4B7690A680E5EAC9BDC78E21117B523622607BCA47305EB74984CF901,"
            "IMPHASH=8461651332BA942E21A64DBF3E9E80F8"
        ),
        "Signed": "true",
        "Signature": "Microsoft Windows",
        "SignatureStatus": "Valid",
        "ProcessGuid": "{32aa854b-cba6-5eac-3503-000000000300}",
        "ProcessId": "1992",
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "UserID": "S-1-5-18",
        "AccountName": "SYSTEM",
        "Domain": "NT AUTHORITY",
        "RuleName": "-",
        "Message": (
            "Image loaded:\r\nRuleName: -\r\n"
            f"ImageLoaded: {loaded}\r\nSigned: true\r\n"
            "Signature: Microsoft Windows\r\nSignatureStatus: Valid"
        ),
    }


def winlog_sysmon_module() -> dict[str, Any]:
    """Newer nested winlog layout of a Sysmon event 7."""
    loaded = flat_sysmon_module()["ImageLoaded"]
    return {
        "@timestamp": SYS_UTC,
        "host": {"name": "web01.example.com"},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer_name": "web01.example.com",
            "event_id": 7,
            "record_id": 401,
            "event_data": {
                "UtcTime": SYS_UTCTIME,
                "ProcessGuid": "{32aa854b-cba6-5eac-3503-000000000300}",
                "ProcessId": 1992,
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "ImageLoaded": loaded,
                "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)",
                "Description": "WMI",
                "Product": "Microsoft Windows Operating System",
                "Company": "Microsoft Corporation",
                "OriginalFileName": "wmidcom.dll",
                "Hashes": "SHA1=4C7308C2A323D850C3E5DCB88A32A1C7DF9CBE4F,"
                "MD5=A9BC5F3E3C6406C3C5ABE804FBF7BC76",
                "Signed": "true",
                "Signature": "Microsoft Windows",
                "SignatureStatus": "Valid",
                "User": "EXAMPLE\\jdoe",
            },
        },
    }


def flat_security_task_xml() -> dict[str, Any]:
    """Flat Security 4698 with a well-formed namespaced task XML blob."""
    record = flat_security_task()
    record["EventIdx"] = 123
    record["TaskContentNew"] = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Actions><Exec>"
        "<Command>powershell.exe</Command>"
        "<Arguments>-NoProfile -Command Get-Process</Arguments>"
        "</Exec></Actions></Task>"
    )
    return record


def flat_sysmon_registry_rename() -> dict[str, Any]:
    """Flat Sysmon event 14 (registry key renamed)."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 14,
        "EventIdx": 121,
        "Hostname": "web01.example.com",
        "TimeCreated": SYS_UTC,
        "UtcTime": SYS_UTCTIME,
        "TargetObject": "HKLM\\SOFTWARE\\ExampleCorp\\OldName",
        "NewName": "HKLM\\SOFTWARE\\ExampleCorp\\NewName",
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4321,
        "Image": "C:\\Windows\\regedit.exe",
        "UserID": "S-1-5-18",
        "AccountName": "SYSTEM",
        "Domain": "NT AUTHORITY",
        "EventTypeOrignal": "INFO",
    }


def evtx_rpc_no_channel() -> dict[str, Any]:
    """Nested ``.evtx`` JSON shape of a channel-less ETW RPC event."""
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-RPC"}},
                "EventID": 5,
                "Channel": None,
                "Computer": "web01.example.com",
                "EventRecordID": 202,
                "TimeCreated": {"#attributes": {"SystemTime": SYS_UTC}},
            },
            "EventData": {
                "ProcNum": "0x0",
                "Protocol": "ncacn_ip_tcp",
                "NetworkAddress": "192.0.2.10",
            },
        }
    }


def flat_lowercase_channel_logon() -> dict[str, Any]:
    """Flat Security 4624 with a lowercase channel spelling, as in OTRF."""
    record = flat_security_logon(success=True)
    record["Channel"] = "security"
    record["EventIdx"] = 111
    return record


def old_beat_sysmon_network() -> dict[str, Any]:
    """Older winlogbeat layout: envelope keys plus payload under event_data."""
    return {
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 3,
        "record_number": 301,
        "computer_name": "web01.example.com",
        "@timestamp": SYS_UTC,
        "source_name": "Microsoft-Windows-Sysmon",
        "message": "Network connection detected (invented text).",
        "host": {"name": "web01.example.com"},
        "user": {"name": "jdoe", "domain": "EXAMPLE"},
        "event_data": {
            "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
            "ProcessId": 4321,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "User": "EXAMPLE\\jdoe",
            "Protocol": "tcp",
            "SourceIp": "192.0.2.10",
            "SourcePort": 52310,
            "DestinationIp": "203.0.113.7",
            "DestinationPort": 443,
            "UtcTime": SYS_UTCTIME,
        },
    }


def old_beat_security_logon() -> dict[str, Any]:
    """Older winlogbeat layout of a Security 4624 logon."""
    return {
        "log_name": "Security",
        "event_id": 4624,
        "record_number": 302,
        "computer_name": "web01.example.com",
        "@timestamp": SYS_UTC,
        "source_name": "Microsoft-Windows-Security-Auditing",
        "host": {"name": "web01.example.com"},
        "event_data": {
            "TargetUserName": "jdoe",
            "TargetDomainName": "EXAMPLE",
            "LogonType": 3,
            "IpAddress": "198.51.100.23",
            "IpPort": 4444,
            "WorkstationName": "client01.example.com",
        },
    }


def winlog_sysmon_file() -> dict[str, Any]:
    """Newer nested winlog layout of a Sysmon event 11."""
    return {
        "@timestamp": SYS_UTC,
        "host": {"name": "db01.example.com"},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer_name": "db01.example.com",
            "event_id": 11,
            "record_id": 303,
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_data": {
                "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
                "ProcessId": 4321,
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "User": "EXAMPLE\\svc-backup",
                "TargetFilename": "C:\\Temp\\dropper.bin",
                "UtcTime": SYS_UTCTIME,
            },
        },
    }


def _winlog_envelope(
    *,
    channel: str,
    event_id: int,
    record_id: int,
    computer: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Wrap a flat-style payload in the newer nested winlog layout."""
    return {
        "@timestamp": SYS_UTC,
        "host": {"name": computer},
        "winlog": {
            "channel": channel,
            "computer_name": computer,
            "event_id": event_id,
            "record_id": record_id,
            "provider_name": channel,
            "event_data": payload,
        },
    }


def winlog_sysmon_registry_key() -> dict[str, Any]:
    """Newer nested winlog layout of a Sysmon event 12.

    Here ``EventType`` is real (no NXLog severity overwrite), so the
    payload carries the operation in the field and no ``Message``.
    """
    flat = flat_sysmon_registry_key()
    payload = {
        key: flat[key]
        for key in (
            "TargetObject",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "UserID",
            "AccountName",
            "Domain",
            "RuleName",
            "UtcTime",
        )
    }
    payload["EventType"] = "CreateKey"
    return _winlog_envelope(
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=12,
        record_id=304,
        computer="web01.example.com",
        payload=payload,
    )


def winlog_sysmon_registry_value() -> dict[str, Any]:
    """Newer nested winlog layout of a Sysmon event 13.

    Here ``EventType`` is real (no NXLog severity overwrite), so the
    payload carries the operation in the field and no ``Message``.
    """
    flat = flat_sysmon_registry_value()
    payload = {
        key: flat[key]
        for key in (
            "TargetObject",
            "Details",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "UserID",
            "AccountName",
            "Domain",
            "RuleName",
            "UtcTime",
        )
    }
    payload["EventType"] = "SetValue"
    return _winlog_envelope(
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=13,
        record_id=305,
        computer="web01.example.com",
        payload=payload,
    )


def winlog_sysmon_registry_rename() -> dict[str, Any]:
    """Newer nested winlog layout of a Sysmon event 14."""
    flat = flat_sysmon_registry_rename()
    payload = {
        key: flat[key]
        for key in (
            "TargetObject",
            "NewName",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "UserID",
            "AccountName",
            "Domain",
            "EventTypeOrignal",
            "UtcTime",
        )
    }
    return _winlog_envelope(
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=14,
        record_id=306,
        computer="web01.example.com",
        payload=payload,
    )


def winlog_security_service() -> dict[str, Any]:
    """Newer nested winlog layout of a Security 4697 service install."""
    flat = flat_security_service()
    payload = {
        key: flat[key]
        for key in (
            "ServiceName",
            "ServiceFileName",
            "ServiceStartType",
            "ServiceType",
            "ServiceAccount",
            "SubjectUserName",
            "SubjectDomainName",
            "TimeCreated",
        )
    }
    return _winlog_envelope(
        channel="Security",
        event_id=4697,
        record_id=307,
        computer="web01.example.com",
        payload=payload,
    )


def winlog_system_service() -> dict[str, Any]:
    """Newer nested winlog layout of a System 7045 service install."""
    flat = flat_service_install(channel="System")
    payload = {
        key: flat[key]
        for key in (
            "ServiceName",
            "ImagePath",
            "StartType",
            "ServiceType",
            "AccountName",
            "Domain",
            "UserID",
            "TimeCreated",
        )
    }
    return _winlog_envelope(
        channel="System",
        event_id=7045,
        record_id=308,
        computer="web01.example.com",
        payload=payload,
    )
