# Linux Sigma coverage (report only, no engine changes)

Date: 2026-10-30 (maintainer local, UTC-6). Producing commands:
`uv run python eval/linux_census.py` (baseline) and the route survey
below (run from the repo root; every number carries its n).

## Rule inventory (n=149)

`data/sigma/sigma_all_rules.zip` holds 149 `rules/linux/*.yml`
rules (n=149, counted from the zip listing): `process_creation` 90,
`auditd` service 27, `file_event` 6, `network_connection` 5, and 21
`builtin` rules (generic keyword rules plus `clamav` 1, `cron` 1,
`guacamole` 1, `sshd` 1, `syslog` 2, `vsftpd` 1, product-only 14).
Status: `test` 130, `experimental` 15, `stable` 4 (n=149, read from
the rule headers). The pinned evaluation set the engine loads,
`data/sigma/rules/builtin/`, holds 285 `product: windows` rules and
zero Linux rules (n=285+0, `grep -rh product:` over that directory).

## Routability (n=149)

`corvus.detect.mapping.route_logsource` returns `None` for all 149
Linux logsource shapes (n=149, surveyed by calling the router on
each rule's product/category/service): the engine routes
`product: windows` only, so every Linux rule is skipped and counted
under its logsource, never evaluated.

## False positives on the benign baseline (n=157451)

Zero rules evaluated, zero findings, zero false positives
(window 2026-10-28T00:00:01Z..2026-10-31T00:00:00Z, n=157451 from
`uv run python eval/linux_census.py`). The zero is vacuous: with no
Linux route there is nothing to fire, so this baseline cannot yet
gate Linux rule precision. Re-measure after the routes land.

## What the engine lacks (feeds the next prompt)

- Routes: `linux/process_creation`, `linux/file_event`,
  `linux/network_connection`, `linux/auditd`,
  `linux/syslog|sshd|cron` have no `route_logsource` entry and no
  field map. The Sysmon-anchored columns (`EventID`, `Channel`,
  `Provider_Name` constants) need Linux equivalents (audit serial /
  record type, decoder name).
- Mostly mappable: `process_creation` (n=90) leans on `Image` (111
  uses), `CommandLine` (151), `ParentImage`/`ParentCommandLine`
  (6+8), `User` (2) — all have OCSF slots on the new 1007 events
  (`process.file.path`, `process.cmd_line`, `parent_process`,
  `actor.user`). `LogonId` (2) and `CurrentDirectory` (2) have no
  slot and would join `unmapped`. `file_event` (n=6):
  `TargetFilename` (7) maps to `file.path`, `Image` (2) to the actor
  process. `network_connection` (n=5): `DestinationIp`/`DestinationPort`
  map to `dst_endpoint`, `Image` (1) to the actor process;
  `Initiated` (2) and `DestinationHostname` (3) have no slot.
- Needs a shape decision: `auditd`-service rules (n=27) match raw
  audit record shapes (`type: PATH/SYSCALL/EXECVE`, `a0..a7`,
  `exe`, `key`, `name`, `comm`, `SYSCALL`, `nametype`) while the new
  normalizer merges one serial into one event (1007/1001/4001 by
  syscall). Fields like `type` and per-record `aN` do not exist
  per stored row the way Sigma expects; the engine must either map
  them onto the merged columns (`aN` onto `process.cmd_line`
  tokens, `name` onto `file.path`, `key` read verbatim) or evaluate
  auditd rules against the raw record. Singles (`comm` 1, `euid`
  1, `unit` 1, `path` 1) are unmapped today.
- Keyword-only rules (generic 11, clamav/cron/sshd/syslog/vsftpd
  service rules) need only a route onto the raw-record keyword
  search; no field map.
- Status gate already fits: 134 of the 149 (stable 4 + test 130)
  would evaluate under the existing status rule; 15 experimental
  stay skipped by the same counting the engine uses for Windows.
