# Linux baseline census (benign, no attack)

Date: 2026-10-30 (maintainer local, UTC-6). Producing command for every
number below: `uv run python eval/linux_census.py` (script
`eval/linux_census.py`), over `data/lab-archives/ossec-archive-*.json.gz`.

## What this baseline is

The baseline holds benign lab activity only: cron sessions opening and
closing every few minutes, systemd unit chatter, monitoring (netstat
scans, `df -P`, syscollector inventory, sysstat `sa1`, chronyd NTP
sync), package (dpkg) bookkeeping, and a handful of ssh publickey
logins with matching disconnects. It holds no attack: no `Failed
password`, no `Invalid user`, and none of the firing rules is an
attack signature (list in "Rule ids" below).

## Scope (n=157451, window 2026-10-28T00:00:01Z..2026-10-31T00:00:00Z)

- Files (n=157451): 3 (`ossec-archive-28.json.gz`,
  `ossec-archive-29.json.gz`, `ossec-archive-30.json.gz`).
- Lines (n=157451, window above): 157451 documents, 0 bad/non-JSON
  lines (producing command above).
- Window (n=157451): 2026-10-28T00:00:01Z to 2026-10-31T00:00:00Z,
  three full days (epoch ms 1793145601367..1793404800926, producing
  command above).

## Counts by facet (each n=157451, producing command above)

- By agent: `000` (server) 23812; `001` (Linux victim) 133639.
- By location: `/var/log/audit/audit.log` 115701; `journald` 13631;
  `df -P` 10090; `syscollector` 10802; `/var/log/dpkg.log` 2318;
  `/var/log/auth.log` 1155; `last -n 20` 1447; `netstat listening
  ports` 1447; `sca` 762; `rootcheck` 37; `wazuh-monitord` 7;
  `logcollector` 13; `wazuh-remoted` 4; `wazuh-agent` 24;
  `vulnerability-detector` 8; `syscheck` 5.
- By decoder: `auditd/auditd` 111391; `auditd` (no parent) 4310;
  `systemd` 5356; `ossec` 13004; `ossec/ossec` 8; `pam/pam` 3208;
  `sshd/sshd` 124; `sshd` (no parent) 12; `syscollector` 10802;
  `kernel` 142; `kernel/kernel` 73; `dpkg-decoder` 2137;
  `windows-date-format` 181; `rootcheck` 37; `sca` 762; `freeipa` 2;
  `su/su` 1; `sudo/sudo` 1; `syscheck_integrity_changed` 5;
  `wazuh/wazuh` 20; `json` 8; none (no decoder) 5867.
- By predecoder program: none 142665; `systemd` 4913; `CRON` 4101;
  `snapd` 2652; `opensearch-dashboards` 1462; `dbus-daemon` 356;
  `sshd` 243; `kernel` 215; `auditd` 105; `systemd-logind` 160;
  `polkitd` 160; `apt.systemd.daily` 164; others (`sudo`, `su`,
  `chronyd`, `rsyslogd`, `(sd-pam)`, `(systemd)`, `systemd-networkd`,
  `systemd-resolved`, `systemd-udevd`, `systemd-journald`,
  `50-motd-news`, `PackageKit`, `adduser`, `cloud-init`, `env`,
  `multipathd`, `kernel`, `snapd` remainders) under 100 each.
- By auditd record type: `SYSCALL` 107008; `EXECVE` 1746; `SERVICE_START`
  642; `SERVICE_STOP` 632; `CRED_ACQ` 528; `LOGIN` 527; `USER_ACCT` 529;
  `USER_START` 529; `USER_END` 526; `CRED_DISP` 526; `CRED_REFR` 523;
  `BPF` 545; `CWD` 353; `PATH` 543; `TRUSTED_APP` 147; `AVC` 76;
  `PROCTITLE` 312; `BPRM_FCAPS` 7; `USER_AUTH` 1; `USER_CMD` 1;
  non-auditd documents (no `data.audit`) 41750.
- By rule id: none (no rule block) 156222; `2904` (dpkg half
  configured) 474; `2902` (dpkg installed) 291; `533` (listened ports
  changed) 13; `80730` (auditd SELinux check) 76; `5501` (PAM session
  opened) 70; `5502` (PAM session closed) 62; `5715` (sshd auth
  success) 54; `1002` (unknown problem) 82; `550`/`5403`/`502`/`503`/
  `506`/`591` (syscheck, sudo-first-use, agent/server lifecycle, log
  rotation) under 20 each; `sca` 19003/19004/19010/19011 (CIS
  benchmark summaries) 40 total; `wazuh` queue rules 202/203/205 20
  total; `json` 23502 (CVE fixed by update) 8; `dpkg-decoder` 2901 4.

## Current-normalizer coverage (n=157451, producing command above)

- Mapped: 107103 (`1007` Process Activity 107009 = every `SYSCALL`
  document plus the one sudo record; `3002` Authentication 89 of 136
  sshd documents; `1001` File System Activity 5 syscheck records).
- Unmapped: 50348, top buckets `ossec` (no rule) 12970, `syscollector`
  10802, `auditd` (no rule) 8617 (every standalone `EXECVE`, `CWD`,
  `PATH`, `PROCTITLE`, `BPF`, `SERVICE_*`, `CRED_*`, `LOGIN`,
  `USER_*` record: `data.audit.type` is not `SYSCALL`), no-decoder
  5785, `systemd` 5356, `pam` (no rule) 3076, `dpkg-decoder` (no rule)
  1368, `sca` (no rule) 722, `pam` with rules 5501/5502 132, `auditd`
  80730 76, `sshd` (no rule) 47 (disconnect/closed lines with no
  decoded user), plus smaller buckets under 300 each.
- The gaps the next step closes: sshd disconnect/closed lines, PAM
  session opened/closed (the 3076 + 132 above), `EXECVE` hex arguments
  joined to their `SYSCALL`, watch-key `PATH` joins, `USER_*` session
  records, and the auth.log/journald duplicates.
- Connect syscalls with addresses ARE present (keys
  `network_connect_4` 2286 and `network_connect_6` 1731, n=157451,
  producing command above): each `full_log` carries a decoded
  `SADDR={ saddr_fam=inet/inet6 laddr=... lport=... }` line. Missing is
  only the mapping, not the data or a rule: `data.audit` drops the
  `SOCKADDR` record, so the mapper reads the address from `full_log`.
