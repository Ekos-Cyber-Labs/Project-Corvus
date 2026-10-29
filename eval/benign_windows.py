"""Synthetic benign Windows baseline (DECLARED SYNTHETIC everywhere reported).

Generates flat NXLog-layout JSON-lines records — the same layout
``corvus/normalize/windows.py`` already reads via ``extract_flat_parts`` —
packs them as ``events.json`` inside a ``.zip`` (the OTRF container shape,
so directory replay loads pick it up; bare ``.json`` files are skipped by
directory scans), and writes the bundle under ``data/benign/`` (git-ignored,
never committed). Load it explicitly or by directory::

    uv run python eval/benign_windows.py --hosts 4 --hours 24 --seed 7
    corvus replay load data/benign/benign_windows_h4_24h_seed7.zip \\
        --replay-dir data/replay-benign --data-dir data

Every number below reproduces from this script with the same arguments.

Per-host counts scale with ``--hours`` as a per-hour rate (see
``BASE_24H``): the 24 h default reproduces the base mix exactly, shorter
spans keep at least one record per category.

Benign-only review (checked against the mapped ``(channel, event id)`` set
and the Sigma rule intent before publishing; nothing here performs,
attempts, or stages an attack technique):

- Logons (Security 4624/4625): interactive ``LogonType`` 2 for invented
  human users, ``LogonType`` 5 for invented service accounts. The few
  4625 failures are mistyped-account typos (``ana.lopezz``) with NO success
  afterwards — an isolated typo, not a password spray (2 failures per host,
  under the correlation failure threshold, and factor 4 needs a success).
- Processes (Sysmon 1): OS and admin binaries only (``explorer.exe``,
  ``svchost.exe -k netsvcs``, ``msiexec.exe /V``, ``TiWorker.exe``,
  ``SearchIndexer.exe``, ``notepad.exe``, plain ``Get-Service`` /
  ``Get-Process`` one-liners). No ``-EncodedCommand``, no
  ``Invoke-Expression``/``IEX``, no ``DownloadString``/``WebClient``, no
  ``-Bypass``/``-Hidden``, no credential, discovery-sweep, or lateral
  tooling (no ``whoami``/``ipconfig``/``net.exe``/``psexec``/``mimikatz``).
  Single benign cmdlets may still trip discovery rules; those matches are
  reported as false positives, never tuned away silently.
- Scheduled tasks (Security 4698 + TaskScheduler 106): OS update and
  Defender tasks whose Exec commands are on-disk Microsoft binaries
  (``usoclient.exe StartScan``, ``MpCmdRun.exe -Scan``), never
  powershell/cmd one-liners.
- Registry (Sysmon 12/13): installer writes by ``msiexec.exe`` under
  ``HKLM\\SOFTWARE\\ExampleCorp``, including ``...\\CurrentVersion\\Run``
  values pointing at ``C:\\Program Files\\...`` binaries (a legitimate
  installer registering its own autostart). Persistence rules may still
  fire on Run keys; those matches are reported, with this documented
  benign cause, not renamed away.
- PowerShell (4104/4103/800): benign ``Get-Service``/``Get-Process``
  invocations only, same exclusions as processes above. The 4103
  ``ContextInfo`` names the real interactive host application
  (``powershell.exe``); an invented ``ConsoleHost`` string without it
  trips the alternate-host rule on the record shape rather than on any
  behaviour, so the realistic value is used and the rule outcome is
  reported, not hidden.
- Parents: service binaries (svchost, msiexec, TiWorker, SearchIndexer)
  are parented by ``services.exe``; only user apps hang under
  ``explorer.exe``. An ``explorer.exe`` svchost parent is genuinely
  suspicious (it is what the uncommon-parent rule hunts), so the benign
  set uses the real shape.
- LSASS (Sysmon 10): ``GrantedAccess 0x1000`` queries from ``services.exe``
  / ``svchost.exe`` with an ``ntdll.dll``-only CallTrace. Only dumping-grade
  masks count as credential access (see ``eval/chain_ground_truth.py``);
  ``0x1000`` is the routine query right and must not match.
- Services (Security 4697 + System 7045): one invented-vendor update
  service under ``C:\\Program Files\\...`` per host.
- Files (Sysmon 11): installer drops under ``C:\\Program Files\\...`` only,
  never Temp/AppData random names.

All hosts are ``wsNN.example.com``; all addresses are RFC 5737
(``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``); all users are
invented. Deterministic per seed: the same ``(seed, hosts, hours, start)``
always yields byte-identical bundles.
"""

from __future__ import annotations

import argparse
import json
import random
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_SEED = 7
DEFAULT_HOSTS = 4
DEFAULT_HOURS = 24
DEFAULT_START = "2024-05-02T00:00:00Z"
MEMBER_NAME = "events.json"

#: Fixed zip member timestamp: ``ZipFile.writestr`` with a bare name stamps
#: the current time, so two runs a second apart differ byte-for-byte even
#: with identical records. A ``ZipInfo`` with this ``date_time`` keeps the
#: bundle byte-stable (pinned by test, independent of the wall clock).
BUNDLE_DATE_TIME = (2024, 5, 2, 0, 0, 0)

DOMAIN = "EXAMPLE"
USERS = ("ana.lopez", "ben.sosa", "cid.ruiz")
SERVICE_ACCOUNTS = ("svc-update", "svc-backup")
TYPO_USER = "ana.lopezz"

UPDATE_TASKS = (
    (
        "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
        "C:\\Windows\\System32\\usoclient.exe",
        "StartScan",
    ),
    (
        "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan",
        "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
        "-Scan -ScanType 1",
    ),
)

#: (image, command line, parent image): service binaries are parented by
#: ``services.exe`` (their real parent — ``explorer.exe`` as an svchost
#: parent is genuinely suspicious and trips the uncommon-parent rule).
BENIGN_PROCESSES = (
    (
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\explorer.exe",
    ),
    (
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "C:\\Windows\\System32\\services.exe",
    ),
    (
        "C:\\Windows\\System32\\msiexec.exe",
        "C:\\Windows\\System32\\msiexec.exe /V",
        "C:\\Windows\\System32\\services.exe",
    ),
    (
        "C:\\Windows\\WinSxS\\TiWorker.exe",
        "C:\\Windows\\WinSxS\\TiWorker.exe",
        "C:\\Windows\\System32\\services.exe",
    ),
    (
        "C:\\Windows\\System32\\SearchIndexer.exe",
        "C:\\Windows\\System32\\SearchIndexer.exe",
        "C:\\Windows\\System32\\services.exe",
    ),
    (
        "C:\\Windows\\System32\\notepad.exe",
        '"C:\\Windows\\System32\\notepad.exe"',
        "C:\\Windows\\explorer.exe",
    ),
    (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -NoProfile -Command Get-Service",
        "C:\\Windows\\explorer.exe",
    ),
    (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -NoProfile -Command Get-Process",
        "C:\\Windows\\explorer.exe",
    ),
)

BENIGN_SCRIPTS = (
    "Get-Service | Where-Object { $_.Status -eq 'Running' }",
    "Get-Process | Select-Object Name, CPU",
)

#: Invented-vendor install paths (legitimate software, Program Files only).
VENDOR_EXE = "C:\\Program Files\\ExampleCorp\\ExampleApp\\example.exe"
VENDOR_SVC_EXE = "C:\\Program Files\\ExampleCorp\\ExampleApp\\update-svc.exe"


def _fmt_zulu(moment: datetime) -> str:
    """Format as ``2024-05-02T14:03:00.000Z`` (flat TimeCreated layout)."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fmt_utctime(moment: datetime) -> str:
    """Format as ``2024-05-02 14:03:00.000`` (flat Sysmon UtcTime layout)."""
    return moment.strftime("%Y-%m-%d %H:%M:%S.000")


def _nxlog_registry_message(operation: str, target: str, moment: datetime) -> str:
    """NXLog-rendered registry text: the op lives on the EventType line."""
    return (
        "Registry object added or deleted:\r\n"
        "RuleName: -\r\n"
        f"EventType: {operation}\r\n"
        f"UtcTime: {_fmt_utctime(moment)}\r\n"
        "ProcessGuid: {11111111-2222-3333-4444-555555555555}\r\n"
        "ProcessId: 4321\r\n"
        "Image: C:\\Windows\\System32\\msiexec.exe\r\n"
        f"TargetObject: {target}\r\n"
    )


def _task_xml(command: str, arguments: str | None) -> str:
    """Well-formed namespaced task XML whose first Exec names a binary."""
    args = f"<Arguments>{arguments}</Arguments>" if arguments else ""
    return (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        f"<Actions><Exec><Command>{command}</Command>{args}</Exec></Actions></Task>"
    )


#: Per-host 24 h base counts per category. Longer or shorter spans scale
#: each count by ``hours / 24`` (rounded, at least one), so ``--hours``
#: changes volume, not just spread; the 24 h default reproduces the base
#: mix exactly (78 records per host).
BASE_24H = {
    "logon": 20,
    "service_logon": 10,
    "failed_logon": 2,
    "process": 30,
    "task_def": 2,
    "registry_key": 1,
    "registry_value": 1,
    "script_block": 2,
    "module": 1,
    "pipeline": 1,
    "lsass": 3,
    "service_install": 1,
    "file": 1,
}


def scaled_count(base: int, hours: int) -> int:
    """Scale one 24 h base count to ``hours`` (rounded, minimum one)."""
    return max(1, round(base * hours / DEFAULT_HOURS))


def generate(
    *,
    seed: int = DEFAULT_SEED,
    hosts: int = DEFAULT_HOSTS,
    hours: int = DEFAULT_HOURS,
    start: str = DEFAULT_START,
) -> list[dict[str, object]]:
    """Build the benign flat records (sorted by time, deterministic)."""
    if hosts < 1:
        raise ValueError(f"hosts must be >= 1, got {hosts}")
    if hours < 1:
        raise ValueError(f"hours must be >= 1, got {hours}")
    base = datetime.fromisoformat(start.replace("Z", "+00:00"))
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    rng = random.Random(seed)
    records: list[dict[str, object]] = []
    idx = 0
    count = {name: scaled_count(base_n, hours) for name, base_n in BASE_24H.items()}

    def stamp() -> tuple[datetime, str, str]:
        moment = base + timedelta(seconds=rng.randint(0, hours * 3600 - 1))
        return moment, _fmt_zulu(moment), _fmt_utctime(moment)

    for host_no in range(1, hosts + 1):
        hostname = f"ws{host_no:02d}.example.com"
        host_ip = f"192.0.2.{10 + host_no}"
        user = USERS[(host_no - 1) % len(USERS)]
        svc = SERVICE_ACCOUNTS[(host_no - 1) % len(SERVICE_ACCOUNTS)]

        for _ in range(count["logon"]):
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Security",
                    "EventID": 4624,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "TargetUserName": user,
                    "TargetDomainName": DOMAIN,
                    "LogonType": 2,
                    "IpAddress": host_ip,
                    "IpPort": 50000 + rng.randint(0, 9999),
                    "WorkstationName": hostname,
                    "_moment": moment,
                }
            )
        for _ in range(count["service_logon"]):
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Security",
                    "EventID": 4624,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "TargetUserName": svc,
                    "TargetDomainName": DOMAIN,
                    "LogonType": 5,
                    "IpAddress": "127.0.0.1",
                    "IpPort": 0,
                    "WorkstationName": hostname,
                    "_moment": moment,
                }
            )
        for _ in range(count["failed_logon"]):
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Security",
                    "EventID": 4625,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "TargetUserName": TYPO_USER,
                    "TargetDomainName": DOMAIN,
                    "LogonType": 2,
                    "IpAddress": f"198.51.100.{20 + host_no}",
                    "IpPort": 51000 + rng.randint(0, 999),
                    "WorkstationName": f"client{host_no:02d}.example.com",
                    "_moment": moment,
                }
            )

        for _ in range(count["process"]):
            moment, created, utctime = stamp()
            image, cmdline, parent_image = rng.choice(BENIGN_PROCESSES)
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 1,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "UtcTime": utctime,
                    "ProcessGuid": f"{{11111111-2222-3333-4444-{idx:012d}}}",
                    "ProcessId": 4000 + rng.randint(0, 999),
                    "Image": image,
                    "CommandLine": cmdline,
                    "User": f"{DOMAIN}\\{user}",
                    "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
                    "ParentProcessId": 1234,
                    "ParentImage": parent_image,
                    "ParentCommandLine": parent_image,
                    "_moment": moment,
                }
            )

        for task_no in range(count["task_def"]):
            task_name, command, arguments = UPDATE_TASKS[task_no % len(UPDATE_TASKS)]
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Security",
                    "EventID": 4698,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "SubjectUserName": "SYSTEM",
                    "SubjectDomainName": "NT AUTHORITY",
                    "TaskName": task_name,
                    "TaskContentNew": _task_xml(command, arguments),
                    "_moment": moment,
                }
            )
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-TaskScheduler/Operational",
                    "EventID": 106,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "TaskName": task_name,
                    "User": f"{DOMAIN}\\{user}",
                    "UserData": "Task registered during OS update servicing.",
                    "_moment": moment,
                }
            )

        key_target = "HKLM\\SOFTWARE\\ExampleCorp\\ExampleApp"
        for _ in range(count["registry_key"]):
            moment, created, utctime = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 12,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "UtcTime": utctime,
                    "EventType": "INFO",
                    "TargetObject": key_target,
                    "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
                    "ProcessId": 4321,
                    "Image": "C:\\Windows\\System32\\msiexec.exe",
                    "UserID": "S-1-5-18",
                    "AccountName": "SYSTEM",
                    "Domain": "NT AUTHORITY",
                    "RuleName": "-",
                    "Message": _nxlog_registry_message("CreateKey", key_target, moment),
                    "_moment": moment,
                }
            )
        run_target = (
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ExampleApp"
        )
        for _ in range(count["registry_value"]):
            moment, created, utctime = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 13,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "UtcTime": utctime,
                    "EventType": "INFO",
                    "TargetObject": run_target,
                    "Details": VENDOR_EXE,
                    "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
                    "ProcessId": 4321,
                    "Image": "C:\\Windows\\System32\\msiexec.exe",
                    "UserID": "S-1-5-18",
                    "AccountName": "SYSTEM",
                    "Domain": "NT AUTHORITY",
                    "RuleName": "-",
                    "Message": _nxlog_registry_message("SetValue", run_target, moment),
                    "_moment": moment,
                }
            )

        for script_no in range(count["script_block"]):
            script = BENIGN_SCRIPTS[script_no % len(BENIGN_SCRIPTS)]
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-PowerShell/Operational",
                    "EventID": 4104,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "User": f"{DOMAIN}\\{user}",
                    "ScriptBlockText": script,
                    "ScriptBlockId": f"{{cccccccc-9999-aaaa-bbbb-{idx:012d}}}",
                    "MessageNumber": 1,
                    "MessageTotal": 1,
                    "_moment": moment,
                }
            )
        for _ in range(count["module"]):
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-PowerShell/Operational",
                    "EventID": 4103,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "AccountName": user,
                    "Domain": DOMAIN,
                    "Payload": 'CommandInvocation(Get-Service): "Get-Service"',
                    "ContextInfo": (
                        "Host Application = "
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    ),
                    "_moment": moment,
                }
            )
        for _ in range(count["pipeline"]):
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Windows PowerShell",
                    "EventID": 800,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "Message": (
                        "Pipeline execution details for command line: Get-Service"
                    ),
                    "_moment": moment,
                }
            )

        for _ in range(count["lsass"]):
            moment, created, utctime = stamp()
            source_image = rng.choice(
                (
                    "C:\\Windows\\System32\\services.exe",
                    "C:\\Windows\\System32\\svchost.exe",
                )
            )
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 10,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "UtcTime": utctime,
                    "TargetProcessGUID": "{aaaaaaaa-1111-2222-3333-444444444444}",
                    "TargetProcessId": 888,
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "SourceProcessGUID": f"{{bbbbbbbb-5555-6666-7777-{idx:012d}}}",
                    "SourceProcessId": 700 + rng.randint(0, 99),
                    "SourceThreadId": 5678,
                    "SourceImage": source_image,
                    "GrantedAccess": "0x1000",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9e0c0",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "ProcessGuid": "{aaaaaaaa-1111-2222-3333-444444444444}",
                    "ProcessId": 888,
                    "Image": "C:\\Windows\\System32\\lsass.exe",
                    "_moment": moment,
                }
            )

        for _ in range(count["service_install"]):
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Security",
                    "EventID": 4697,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "ServiceName": "ExampleCorp Update Service",
                    "ServiceFileName": VENDOR_SVC_EXE,
                    "ServiceStartType": "2",
                    "ServiceType": "0x10",
                    "ServiceAccount": "LocalSystem",
                    "SubjectUserName": "SYSTEM",
                    "SubjectDomainName": "NT AUTHORITY",
                    "_moment": moment,
                }
            )
            moment, created, _ = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "System",
                    "EventID": 7045,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "ServiceName": "ExampleCorp Update Service",
                    "ImagePath": VENDOR_SVC_EXE,
                    "StartType": "auto start",
                    "ServiceType": "user mode service",
                    "AccountName": "SYSTEM",
                    "Domain": "NT AUTHORITY",
                    "UserID": "S-1-5-18",
                    "_moment": moment,
                }
            )

        for _ in range(count["file"]):
            moment, created, utctime = stamp()
            idx += 1
            records.append(
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 11,
                    "EventIdx": idx,
                    "Hostname": hostname,
                    "TimeCreated": created,
                    "UtcTime": utctime,
                    "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
                    "ProcessId": 4321,
                    "Image": "C:\\Windows\\System32\\msiexec.exe",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "TargetFilename": VENDOR_EXE,
                    "_moment": moment,
                }
            )

    records.sort(key=lambda record: (str(record["_moment"]), int(record["EventIdx"])))  # type: ignore[arg-type]
    for record in records:
        del record["_moment"]
    return records


def bundle_name(*, hosts: int, hours: int, seed: int) -> str:
    """File name encoding the parameters (reproduces the default --out)."""
    return f"benign_windows_h{hosts}_{hours}h_seed{seed}.zip"


def write_bundle(records: list[dict[str, object]], out_path: Path) -> Path:
    """Write records as ``events.json`` JSON-lines inside a ``.zip``.

    The member carries the fixed ``BUNDLE_DATE_TIME`` instead of the
    current time, so the same records always yield identical bytes.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    info = zipfile.ZipInfo(MEMBER_NAME, date_time=BUNDLE_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(out_path, "w") as bundle:
        bundle.writestr(
            info,
            "".join(json.dumps(record) + "\n" for record in records),
        )
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=int, default=DEFAULT_HOSTS)
    parser.add_argument("--hours", type=int, default=DEFAULT_HOURS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--start", default=DEFAULT_START)
    parser.add_argument(
        "--out",
        default=None,
        help="Bundle path (default: data/benign/<params>.zip).",
    )
    args = parser.parse_args(argv)

    records = generate(
        seed=args.seed, hosts=args.hosts, hours=args.hours, start=args.start
    )
    out_path = (
        Path(args.out)
        if args.out
        else REPO_ROOT
        / "data"
        / "benign"
        / bundle_name(hosts=args.hosts, hours=args.hours, seed=args.seed)
    )
    if not out_path.is_absolute():
        out_path = Path.cwd() / out_path
    out_path = out_path.resolve()
    try:
        out_path.relative_to(REPO_ROOT)
    except ValueError:
        print("error: --out must stay inside the repository")
        return 2
    write_bundle(records, out_path)
    print(
        f"synthetic benign Windows set (DECLARED SYNTHETIC): "
        f"n={len(records)} records, hosts={args.hosts}, "
        f"hours={args.hours}, seed={args.seed} -> {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
