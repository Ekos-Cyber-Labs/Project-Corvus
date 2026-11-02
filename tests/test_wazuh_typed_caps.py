"""Bounds on typed Wazuh/Linux strings (same cap as ``raw_data``).

Every string the Wazuh alert/archive mappers and the Linux loader
copy into a typed slot, a finding title or an entity key truncates at
:data:`WAZUH_RAW_DATA_CAP` with the original length kept in
``unmapped`` under a per-field ``*_truncated`` key. Shapes are real
fixtures from ``tests/fixtures/wazuh/`` and ``tests/fixtures/linux/``;
the 256-character Linux user cap is untouched (covered by the existing
normalizer tests).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from corvus.normalize import wazuh
from corvus.normalize.wazuh import WAZUH_RAW_DATA_CAP
from corvus.normalize.windows import WINDOWS_TEXT_CAP

WAZUH_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
LINUX_FIXTURES = Path(__file__).parent / "fixtures" / "linux"

CAP = WAZUH_RAW_DATA_CAP
BIG = "X" * 5_000_000


def test_caps_match() -> None:
    """The typed-slot cap is the single documented number."""
    assert CAP == WINDOWS_TEXT_CAP


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _string_leaves(item)]
    if isinstance(value, (list, tuple)):
        return [leaf for item in value for leaf in _string_leaves(item)]
    return []


def _assert_typed_bound(event: Any, originals: dict[str, int]) -> None:
    """Every typed string fits the cap; every original length is kept."""
    for leaf in _string_leaves(
        event.model_dump(exclude={"raw_data", "unmapped", "entity_keys"})
    ):
        assert len(leaf) <= CAP
    for key, length in originals.items():
        assert event.unmapped.get(key) == length, key


def _load_hit(name: str) -> dict[str, Any]:
    return json.loads((WAZUH_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _load_doc(name: str) -> dict[str, Any]:
    return json.loads((LINUX_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _alert_description_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sudo")
    hit["_source"]["rule"]["description"] = "Successful sudo " + BIG
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    assert finding.finding_info is not None
    assert finding.finding_info.title is not None
    assert len(finding.finding_info.title) <= CAP
    assert finding.unmapped.get("wazuh.description_truncated") == len(
        hit["_source"]["rule"]["description"]
    )
    return finding, {}


def _alert_agent_name_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sudo")
    hit["_source"]["agent"]["name"] = "web-" + BIG
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    for record in (finding, event):
        assert record.device is not None
        assert record.device.hostname is not None
        assert len(record.device.hostname) <= CAP
        assert record.unmapped.get("wazuh.agent_name_truncated") == len(
            hit["_source"]["agent"]["name"]
        )
    return event, {}


def _alert_agent_ip_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sudo")
    hit["_source"]["agent"]["ip"] = BIG
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    for record in (finding, event):
        assert record.device is not None
        assert record.device.ip is not None
        assert len(record.device.ip) <= CAP
        assert record.unmapped.get("wazuh.agent_ip_truncated") == len(BIG)
    return event, {}


def _alert_sudo_command_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sudo")
    command = "/usr/bin/sudo " + BIG
    hit["_source"]["command"] = command
    hit["_source"].pop("data", None)
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    assert event.process is not None and event.process.cmd_line is not None
    assert len(event.process.cmd_line) <= CAP
    assert event.process.file is not None and event.process.file.path is not None
    assert len(event.process.file.path) <= CAP
    assert event.unmapped.get("wazuh.command_truncated") == len(command)
    return event, {}


def _alert_sudo_users_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sudo")
    hit["_source"]["srcuser"] = "invoking-" + BIG
    hit["_source"]["dstuser"] = "effective-" + BIG
    hit["_source"].pop("data", None)
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    assert event.actor is not None and event.actor.user is not None
    assert event.process is not None and event.process.user is not None
    assert len(event.actor.user.name or "") <= CAP
    assert len(event.process.user.name or "") <= CAP
    assert event.unmapped.get("wazuh.srcuser_truncated") == len(
        hit["_source"]["srcuser"]
    )
    assert event.unmapped.get("wazuh.dstuser_truncated") == len(
        hit["_source"]["dstuser"]
    )
    assert len(event.entity_keys.user or "") < 2 * CAP
    return event, {}


def _alert_sshd_ip_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sshd_success")
    source = hit["_source"]
    # A line with no known message kind leaves the peer unset without
    # flagging it unparsed, so the typed source falls back to the
    # decoded ``srcip`` (attacker-influenced) field.
    source["full_log"] = (
        "May  2 12:01:00 web01 sshd[10031]:"
        " pam_unix(sshd:auth): authentication failure;"
        " logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.1"
    )
    source["data"]["srcuser"] = "deploy"
    source["data"]["srcip"] = BIG
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    assert event.src_endpoint is not None and event.src_endpoint.ip is not None
    assert len(event.src_endpoint.ip) <= CAP
    assert event.unmapped.get("wazuh.src_ip_truncated") == len(BIG)
    return event, {}


def _alert_syscheck_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("syscheck_integrity_changed")
    syscheck = hit["_source"]["data"]["syscheck"]
    syscheck["path"] = "/etc/" + BIG
    syscheck["sha256_after"] = "D" * 5_000_000
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    assert event.file is not None and event.file.path is not None
    assert len(event.file.path) <= CAP
    assert event.unmapped.get("wazuh.syscheck_path_truncated") == len(syscheck["path"])
    assert event.file.hashes is not None
    for fingerprint in event.file.hashes:
        assert len(fingerprint.value or "") <= CAP
    assert event.unmapped.get("wazuh.syscheck_digest_truncated") == 5_000_000
    return event, {}


def _alert_category_big() -> tuple[Any, dict[str, int]]:
    hit = _load_hit("sudo")
    hit["_source"]["rule"]["groups"] = ["syslog", BIG]
    finding, event, key = wazuh.map_alert(hit)
    assert key is None and event is not None
    assert finding.finding_info is not None
    assert finding.finding_info.analytic is not None
    assert finding.finding_info.analytic.category is not None
    assert len(finding.finding_info.analytic.category) <= CAP
    assert finding.unmapped.get("wazuh.category_truncated") == len("syslog," + BIG)
    return finding, {}


def _linux_sudo_command_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("sudo_rec")
    doc["data"]["command"] = "/usr/bin/sudo " + BIG
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.process is not None
    assert event.process.cmd_line is not None
    assert len(event.process.cmd_line) <= CAP
    assert event.unmapped.get("wazuh.command_truncated") == len(doc["data"]["command"])
    return event, {}


def _linux_audit_exe_users_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("exec_hex")
    doc["data"]["audit"]["exe"] = "/usr/bin/" + BIG
    doc["data"]["audit"]["auid"] = BIG
    doc["data"]["audit"]["euid"] = BIG
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.process is not None
    assert event.process.file is not None and event.process.file.path is not None
    assert len(event.process.file.path) <= CAP
    assert event.actor is not None and event.actor.user is not None
    assert len(event.actor.user.name or "") <= CAP
    assert len((event.process.user.name if event.process.user else "") or "") <= CAP
    assert event.unmapped.get("wazuh.audit_exe_truncated") == len(
        doc["data"]["audit"]["exe"]
    )
    assert event.unmapped.get("wazuh.audit_actor_truncated") == len(BIG)
    assert event.unmapped.get("wazuh.audit_user_truncated") == len(BIG)
    return event, {}


def _linux_audit_command_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("exec_hex")
    doc["full_log"] = (
        "type=SYSCALL msg=audit(1793145867.400:999999): arch=c000003e"
        " syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=4 items=0 ppid=1"
        " pid=2 auid=3 uid=4 gid=5 euid=6 suid=7 fsuid=8 egid=9 sgid=10"
        ' fsgid=11 tty=pts0 ses=1 comm="x" exe="/bin/x" key="k"'
        "\nSYSCALL=execve"
    )
    doc["data"]["audit"]["execve"] = {"argc": 1, "a0": "/bin/echo " + BIG}
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.process is not None
    assert event.process.cmd_line is not None
    assert len(event.process.cmd_line) <= CAP
    assert event.unmapped.get("wazuh.audit_command_truncated") == len(
        "/bin/echo " + BIG
    )
    return event, {}


def _linux_file_path_actor_exe_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("file_open")
    doc["full_log"] = re.sub(r'name="[^"]*"', f'name="/tmp/{BIG}"', doc["full_log"])
    doc["data"]["audit"]["auid"] = BIG
    doc["data"]["audit"]["exe"] = "/usr/bin/" + BIG
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.file is not None
    assert event.file.path is not None
    assert len(event.file.path) <= CAP
    assert event.unmapped.get("wazuh.file_path_truncated") == len(f"/tmp/{BIG}")
    assert event.actor is not None and event.actor.user is not None
    assert len(event.actor.user.name or "") <= CAP
    assert event.unmapped.get("wazuh.file_actor_truncated") == len(BIG)
    return event, {}


def _linux_net_peer_actor_exe_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("conn")
    doc["full_log"] = re.sub(r"laddr=\S+", f"laddr={BIG}", doc["full_log"])
    doc["data"]["audit"]["uid"] = BIG
    doc["data"]["audit"]["exe"] = "/usr/bin/" + BIG
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.dst_endpoint is not None
    assert event.dst_endpoint.ip is not None
    assert len(event.dst_endpoint.ip) <= CAP
    assert event.unmapped.get("wazuh.peer_ip_truncated") == len(BIG)
    assert event.actor is not None and event.actor.user is not None
    assert len(event.actor.user.name or "") <= CAP
    assert event.unmapped.get("wazuh.net_actor_truncated") == len(BIG)
    return event, {}


def _linux_user_cmd_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("ucmd")
    command = "/usr/bin/sudo " + BIG
    doc["full_log"] = re.sub(
        r"cmd=[0-9a-fA-F]+", f"cmd={command.encode().hex()}", doc["full_log"]
    )
    doc["full_log"] = doc["full_log"].replace('UID="deploy"', f'UID="{BIG}"')
    doc["full_log"] = doc["full_log"].replace(
        'exe="/usr/bin/sudo"', f'exe="/bin/{BIG}"'
    )
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.process is not None
    assert event.process.cmd_line is not None
    assert len(event.process.cmd_line) <= CAP
    assert event.unmapped.get("wazuh.user_cmd_truncated") == len(command)
    assert event.actor is not None and event.actor.user is not None
    assert len(event.actor.user.name or "") <= CAP
    assert event.unmapped.get("wazuh.user_cmd_actor_truncated") == len(BIG)
    assert event.process.file is not None and event.process.file.path is not None
    assert len(event.process.file.path) <= CAP
    return event, {}


def _linux_session_exe_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("login")
    doc["full_log"] = doc["full_log"].replace(
        'exe="/usr/sbin/cron"', f'exe="/usr/sbin/{BIG}"', 1
    )
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.actor is not None
    assert event.actor.process is not None
    assert event.actor.process.name is not None
    assert len(event.actor.process.name) <= CAP
    assert event.unmapped.get("wazuh.session_exe_truncated") == len(f"/usr/sbin/{BIG}")
    return event, {}


def _linux_pam_actor_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("pam_open")
    assert "by root" in doc["full_log"]
    doc["full_log"] = doc["full_log"].replace("by root", f"by {BIG}")
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.actor is not None
    assert event.actor.user is not None and event.actor.user.name is not None
    assert len(event.actor.user.name) <= CAP
    assert event.unmapped.get("wazuh.pam_actor_truncated") == len(BIG)
    return event, {}


def _linux_su_invoker_big() -> tuple[Any, dict[str, int]]:
    doc = _load_doc("su_rec")
    assert ") root on" in doc["full_log"]
    doc["full_log"] = doc["full_log"].replace(") root on", f") {BIG} on")
    finding, event, key, _ = wazuh.map_linux_doc(doc)
    assert event is not None and event.actor is not None
    assert event.actor.user is not None and event.actor.user.name is not None
    assert len(event.actor.user.name) <= CAP
    assert event.unmapped.get("wazuh.su_invoker_truncated") == len(BIG)
    return event, {}


#: One hostile 5,000,000-character value per typed Wazuh/Linux slot.
_TUPLE_CASES: list[tuple[str, Callable[[], tuple[Any, dict[str, int]]]]] = [
    ("alert-description", _alert_description_big),
    ("alert-agent-name", _alert_agent_name_big),
    ("alert-agent-ip", _alert_agent_ip_big),
    ("alert-sudo-command", _alert_sudo_command_big),
    ("alert-sudo-users", _alert_sudo_users_big),
    ("alert-sshd-ip", _alert_sshd_ip_big),
    ("alert-syscheck", _alert_syscheck_big),
    ("alert-category", _alert_category_big),
    ("linux-sudo-command", _linux_sudo_command_big),
    ("linux-audit-exe-users", _linux_audit_exe_users_big),
    ("linux-audit-command", _linux_audit_command_big),
    ("linux-file-path-actor", _linux_file_path_actor_exe_big),
    ("linux-net-peer-actor", _linux_net_peer_actor_exe_big),
    ("linux-user-cmd", _linux_user_cmd_big),
    ("linux-session-exe", _linux_session_exe_big),
    ("linux-pam-actor", _linux_pam_actor_big),
    ("linux-su-invoker", _linux_su_invoker_big),
]


@pytest.mark.parametrize("case_id", [case_id for case_id, _ in _TUPLE_CASES])
def test_huge_typed_values_capped(case_id: str) -> None:
    """A 5,000,000-character hostile value stays a bounded record."""
    builder = dict(_TUPLE_CASES)[case_id]
    record, _ = builder()
    _assert_typed_bound(record, {})


def test_boundary_cap_intact_and_cap_plus_one_cut() -> None:
    """Exactly the cap passes through; cap + 1 truncates with the length."""
    hit = _load_hit("sudo")
    command = "C" * CAP
    hit["_source"]["command"] = command
    hit["_source"].pop("data", None)
    _, event, _ = wazuh.map_alert(hit)
    assert event is not None and event.process is not None
    assert event.process.cmd_line == command
    assert "wazuh.command_truncated" not in event.unmapped
    over = "C" * (CAP + 1)
    hit["_source"]["command"] = over
    _, event, _ = wazuh.map_alert(hit)
    assert event is not None and event.process is not None
    assert event.process.cmd_line == over[:CAP]
    assert event.unmapped.get("wazuh.command_truncated") == CAP + 1
