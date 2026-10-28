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
