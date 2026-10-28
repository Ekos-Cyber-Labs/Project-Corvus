"""Hand-written OCSF fixture for SIEM adapter tests.

Seven events, two hosts, five log sources, five OCSF classes. All addresses
are RFC 5737 documentation ranges, all hostnames under ``example.com``.
``metadata.log_name`` carries the real telemetry source (never the index
pattern). Times are UTC epoch milliseconds spaced one minute apart from
2026-10-27T12:00:00Z, except ``wazuh-2b`` which shares its timestamp with
``wazuh-2`` to exercise resume tie-breaking on ``metadata.uid``.
"""

from corvus.normalize.ocsf import (
    Authentication,
    DetectionFinding,
    FileSystemActivity,
    NetworkActivity,
    OcsfEvent,
    ProcessActivity,
)

#: 2026-10-27T12:00:00Z as UTC epoch milliseconds.
BASE_TIME_MS = 1793102400000

MINUTE_MS = 60_000


def _product(log_name: str) -> dict[str, object]:
    return {
        "product": {"name": "wazuh", "vendor_name": "Wazuh"},
        "log_name": log_name,
        "uid": None,
    }


def make_siem_fixture_events() -> list[OcsfEvent]:
    """Return the seven fixture events in time order."""
    return [
        Authentication(
            time=BASE_TIME_MS,
            metadata={**_product("Security"), "uid": "wazuh-1"},
            activity_id=1,
            status="Failure",
            status_id=2,
            actor={"user": {"name": "EXAMPLE\\jdoe"}},
            device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
            src_endpoint={"ip": "198.51.100.23", "port": 4444},
        ),
        Authentication(
            time=BASE_TIME_MS + MINUTE_MS,
            metadata={**_product("Security"), "uid": "wazuh-2"},
            activity_id=1,
            status="Success",
            status_id=1,
            actor={"user": {"name": "EXAMPLE\\jdoe"}},
            device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
            src_endpoint={"ip": "198.51.100.23", "port": 4451},
        ),
        Authentication(
            time=BASE_TIME_MS + MINUTE_MS,
            metadata={**_product("Security"), "uid": "wazuh-2b"},
            activity_id=1,
            status="Failure",
            status_id=2,
            actor={"user": {"name": "EXAMPLE\\jdoe"}},
            device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
            src_endpoint={"ip": "198.51.100.23", "port": 4452},
        ),
        ProcessActivity(
            time=BASE_TIME_MS + 2 * MINUTE_MS,
            metadata={
                **_product("Microsoft-Windows-Sysmon/Operational"),
                "uid": "wazuh-3",
            },
            activity_id=1,
            actor={"user": {"name": "EXAMPLE\\jdoe"}},
            device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
            process={
                "pid": 1234,
                "name": "powershell.exe",
                "cmd_line": "powershell -enc x",
                "file": {"path": "C:\\Windows\\System32\\powershell.exe"},
            },
        ),
        NetworkActivity(
            time=BASE_TIME_MS + 3 * MINUTE_MS,
            metadata={**_product("suricata"), "uid": "wazuh-4"},
            activity_id=6,
            action="Allowed",
            action_id=1,
            actor={"user": {"name": "EXAMPLE\\jdoe"}},
            device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
            src_endpoint={"ip": "192.0.2.10", "port": 52310},
            dst_endpoint={"ip": "203.0.113.7", "port": 443},
        ),
        FileSystemActivity(
            time=BASE_TIME_MS + 4 * MINUTE_MS,
            metadata={**_product("syscheck"), "uid": "wazuh-5"},
            activity_id=1,
            actor={"user": {"name": "EXAMPLE\\svc-backup"}},
            device={"hostname": "db01.example.com", "ip": "192.0.2.20"},
            file={"path": "/etc/cron.d/evil"},
        ),
        DetectionFinding(
            time=BASE_TIME_MS + 5 * MINUTE_MS,
            metadata={**_product("wazuh-manager"), "uid": "wazuh-6"},
            activity_id=1,
            severity_id=4,
            actor={"user": {"name": "EXAMPLE\\jdoe"}},
            device={"hostname": "web01.example.com", "ip": "192.0.2.10"},
        ),
    ]
