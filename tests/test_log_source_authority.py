"""Tests pinning which source wins when ``data`` and ``full_log`` disagree.

Rule (also stated in ``docs/architecture.md``): the kernel/audit log
line wins wherever the attacker-influenced Wazuh decode could be
forged -- sshd user/peer (conflict kept in
``linux.decoder_conflict``), auditd EXECVE command line, file paths
and ``USER_CMD`` user/command. Wazuh-decoded ``data`` wins where the
value is kernel-attributed, not attacker-controlled (auditd
auid/uid), and for sudo, whose mapper reads only the decoded fields.
Every disagreement below is synthetic and says so.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from corvus.normalize import wazuh
from corvus.normalize.ocsf import (
    Authentication,
    FileSystemActivity,
    ProcessActivity,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _wazuh_hit(name: str) -> dict:
    return json.loads((FIXTURES / "wazuh" / f"{name}.json").read_text())


def _linux_doc(name: str) -> dict:
    return json.loads((FIXTURES / "linux" / f"{name}.json").read_text())


def test_sudo_decoded_users_win_over_log_line() -> None:
    """Synthetic: ``data`` srcuser/dstuser beat the sudo log line."""
    hit = copy.deepcopy(_wazuh_hit("sudo"))
    hit["_source"]["srcuser"] = "mallory"
    hit["_source"]["dstuser"] = "hacker"
    _finding, event, key = wazuh.map_alert(hit)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "mallory"
    assert event.process is not None and event.process.user is not None
    assert event.process.user.name == "hacker"


def test_sudo_decoded_command_wins_over_log_line() -> None:
    """Synthetic: ``data`` command beats the sudo log line COMMAND."""
    hit = copy.deepcopy(_wazuh_hit("sudo"))
    hit["_source"]["command"] = "/usr/bin/evil --persist"
    _finding, event, key = wazuh.map_alert(hit)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.process is not None
    assert event.process.cmd_line == "/usr/bin/evil --persist"
    assert event.process.name == "evil"


def test_sudo_decoded_pwd_wins_over_log_line() -> None:
    """Synthetic: ``data`` pwd beats the sudo log line PWD."""
    hit = copy.deepcopy(_wazuh_hit("sudo"))
    hit["_source"]["pwd"] = "/tmp/evil"
    _finding, event, key = wazuh.map_alert(hit)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.unmapped.get("pwd") == "/tmp/evil"


def test_auditd_execve_blob_command_wins_over_decoded() -> None:
    """Synthetic: the EXECVE blob beats ``data.audit.execve``/command."""
    doc = copy.deepcopy(_linux_doc("exec_hex"))
    doc["data"]["audit"]["execve"]["a0"] = "/usr/bin/planted"
    doc["data"]["audit"]["command"] = "planted"
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.process is not None
    assert event.process.cmd_line is not None
    assert event.process.cmd_line.startswith("sh -c")
    assert "planted" not in event.process.cmd_line


def test_auditd_execve_users_come_from_decoded_data() -> None:
    """Synthetic: auid/uid (kernel-attributed) come from ``data``."""
    doc = copy.deepcopy(_linux_doc("exec_hex"))
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.actor is not None and event.actor.user is not None
    # auid is unset here, so the decoded uid (root/0) is the actor.
    assert event.actor.user.name == "0"


def test_auditd_file_path_blob_wins_over_decoded() -> None:
    """Synthetic: the PATH blob beats ``data.audit.file.name``."""
    doc = copy.deepcopy(_linux_doc("file_open"))
    doc["data"]["audit"]["file"]["name"] = "/tmp/planted"
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert isinstance(event, FileSystemActivity)
    assert event.file is not None
    assert event.file.path == "/dev/console"


def test_auditd_user_cmd_log_user_wins_over_decoded() -> None:
    """Synthetic: full_log ``UID=`` beats ``data.audit.uid``."""
    doc = copy.deepcopy(_linux_doc("ucmd"))
    doc["data"]["audit"]["uid"] = "hacker"
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.actor is not None and event.actor.user is not None
    assert event.actor.user.name == "deploy"


def test_auditd_user_cmd_command_comes_from_log_line() -> None:
    """The USER_CMD command exists only in the log line ``cmd=<hex>``."""
    doc = _linux_doc("ucmd")
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert isinstance(event, ProcessActivity)
    assert event.process is not None
    assert event.process.cmd_line == "/usr/bin/find /tmp -maxdepth 0"


def test_sshd_log_line_wins_over_decoded_on_archive() -> None:
    """The real lab archive line prefers the log line (no alert needed)."""
    doc = json.loads((FIXTURES / "linux" / "sshd_injection_invalid.json").read_text())
    _finding, event, key, _dedupe = wazuh.map_linux_doc(doc)
    assert key is None
    assert isinstance(event, Authentication)
    assert event.user is not None
    assert event.user.name == ("zz Accepted password for root from 8.8.8.8 port 22")
    assert event.unmapped.get("linux.decoder_conflict") == {
        "user": "root",
        "ip": "8.8.8.8",
        "port": "22",
    }
