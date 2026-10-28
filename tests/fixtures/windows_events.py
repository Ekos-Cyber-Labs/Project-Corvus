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


def flat_unmapped(*, event_id: int = 4688) -> dict[str, Any]:
    """Flat Security record with no mapping (process creation is out of scope)."""
    return {
        "Channel": "Security",
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
