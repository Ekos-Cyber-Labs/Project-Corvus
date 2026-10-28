# APT29 day-1 compound replay load report

Load: `corvus replay load data/security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip` (n = 1 file, 196081 records). Window: 2020-05-02T02:55:26Z to 2020-05-02T03:28:20Z (`@timestamp` min/max over all records), run 2026-10-28. Ground truth: the ordered 10-step chain in [apt29_day1_ground_truth.json](../apt29_day1_ground_truth.json) (chain-level only; this dataset has no per-event labels, so event-level precision cannot be computed on it). Every count below reproduces with `uv run python eval/apt29_census.py`; the load totals reproduce with the load command above. Counts and ids only below, no event content, host names, user names, or script text.

## Load totals

- Files processed: 1. SHA-256 verified before load: `98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5`.
- Runtime and peak memory: measured with `/usr/bin/time -l corvus replay load ...` at report generation; re-run that command to reproduce them. The census pass streams record by record and never holds the dataset in memory.
- Mapped events: 152491. Unmapped records: 43590 in 162 (channel, event id) buckets. Unsupported archive members: 0. Mapped + unmapped = 196081, the full record count.
- Events carrying an in-band technique reference (provenance flag from the load): 0.
- Sysmon 7 mapping cost: this tree vs commit `5d2296d` (same file, same machine, separate `--replay-dir` loads): loader 13.5 s -> 16.2 s; day-1 events Parquet 71165022 bytes -> 92128495 bytes (+20963473 bytes); mapped events 132232 -> 152491 (+20259 Module Activity). Reproduced with `git worktree add /tmp/corvus-before 5d2296d`, `corvus replay load <file> --replay-dir <dir>` on each tree, and `ls -l <dir>/events/b6d3065fbd07eed2.parquet` (slug of the data-relative path).

## Events per OCSF class (n = 152491)

| Class | Events |
|---|---|
| 1001 File System Activity | 1649 |
| 1005 Module Activity | 20259 |
| 1007 Process Activity | 39730 |
| 1009 Script Activity | 10607 |
| 3002 Authentication | 297 |
| 4001 Network Activity | 1229 |
| 201001 Registry Key Activity | 60970 |
| 201002 Registry Value Activity | 17722 |
| 201004 Windows Service Activity | 28 |

Script Activity is PowerShell 4104 plus PowerShell Operational 4103 and Windows PowerShell 800. Authentication includes both `Security` and WEF-forwarded lowercase `security` records under the canonical `Security` channel; a probe found no exact duplicate records across the two spellings. Registry Key Activity is Sysmon 12 CreateKey (Create) and DeleteKey (Delete) plus Sysmon 14 renames; Registry Value Activity is Sysmon 13 value sets (Set) plus Sysmon 12 DeleteValue (Delete). NXLog replaces the flat `EventType` field with the severity, so the op is read from the `Message` `EventType:` line. Windows Service Activity is Security 4697 and System 7045 service installs. Sysmon 7 image loads now map to Module Activity (1005, Load): `ImageLoaded` becomes `module.file` (hashes, description, company, product and original file name typed; signer fields stay in `unmapped`), the loading process is `actor.process`. Scheduled-job commands moved from the deprecated `job.cmd_line` to `job.job_actions[].cmd_line` (type 2 Execute), and win extension classes declare `metadata.extensions` (win, uid "2", version 1.9.0).

Per-activity breakdown of the new classes (n = 60970 + 17722):

- Registry Key Activity (201001): Create 60094, Delete 876, Rename 0.
- Registry Value Activity (201002): Set 17541, Delete 181.

## Top 15 unmapped (channel, event id) buckets (n = 43590 records)

| Channel | Event id | Records |
|---|---|---|
| Security | 4658 | 10973 |
| Security | 4656 | 5497 |
| Security | 4690 | 5471 |
| Security | 4663 | 5337 |
| Security | 5156 | 3163 |
| Security | 5447 | 2587 |
| Security | 5158 | 1896 |
| Security | 4703 | 1802 |
| Security | 4673 | 934 |
| Microsoft-Windows-Sysmon/Operational | 9 | 652 |
| Security | 4688 | 460 |
| Microsoft-Windows-Sysmon/Operational | 23 | 422 |
| Microsoft-Windows-Sysmon/Operational | 5 | 401 |
| Security | 4689 | 398 |
| Microsoft-Windows-Sysmon/Operational | 18 | 362 |

Security buckets are canonical: lowercase `security` records count under `Security`, never as a second channel.

## Ground-truth step visibility (per-step windows, counts only)

Verdict per step: `direct` = at least one mapped event inside the step window whose text fields (process and parent path, command line, script content, file path, registry key/value path/name/data, service name/command line, scheduled-job name/action command line, loaded-module file path/name/description/product) contain a step anchor; `indirect` = no mapped anchor hit but technique-relevant events inside the window; `none` = neither. Anchor hits outside a step window are reported as out-of-window counts, not matches. Step windows were re-derived in the census (min/max ingest time of anchor hits over all records); the difference against the committed window is shown per step. No step changed verdict in the Sysmon 7 mapping pass: all 10 steps were `direct` before and stay `direct`, so no `match_kind` changes in the chain file. Seven steps gained mapped anchor hits — their Sysmon 7 image-load anchors moved from the unmapped bucket into mapped Module Activity events (the loading process name/path carries the anchor; step 1: 65 more, step 3: 68, step 4: 444, step 6: 19, step 8: 219, step 9: 38, step 10: 9 in-window plus 9 out-of-window on step 5) — and the Sysmon 7 unmapped column is now empty on every step. Step 8's last 4 hits are PSEXESVC.exe image loads whose anchor lives only in the typed file description and product (`PsExec Service` / `Sysinternals PsExec`); the ImageLoaded path itself (`PSEXESVC.exe`) does not contain the anchor, which is why the module file fields joined the anchor search. Steps 2, 5 and 7 never referenced an image load and are unchanged.

| Step | Window (UTC) | Anchor hits (mapped, in / out) | Unmapped anchor hits in window | Relevant in window | Verdict |
|---|---|---|---|---|---|
| 1 Initial Breach | 02:55:57-03:02:06 (derived 02:55:57-03:02:06 (+730 / +95 ms)) | 106 / 2 | Microsoft-Windows-Sysmon/Operational 17: 6; Microsoft-Windows-Sysmon/Operational 18: 6; Security 4688: 5; Security 4658: 2; Microsoft-Windows-Sysmon/Operational 22: 2; Security 4673: 1; Security 4656: 1; Security 4663: 1; Security 5158: 1; Security 5156: 1; Security 4689: 1; Microsoft-Windows-Sysmon/Operational 5: 1 | 44 | direct |
| 2 Rapid Collection and Exfiltration | 02:56:18-03:03:16 (derived 02:56:18-03:16:01 (+119 / +765396 ms)) | 41 / 28 | none | 6235 | direct |
| 3 Deploy Stealth Toolkit | 02:57:01-03:08:53 (derived 02:57:01-03:08:53 (+833 / +548 ms)) | 129 / 0 | Windows PowerShell 600: 6; Security 4688: 5; Microsoft-Windows-Sysmon/Operational 5: 3; Security 4689: 3; Security 4658: 2; Security 4656: 1; Security 4663: 1; Windows PowerShell 400: 1 | 45391 | direct |
| 4 Defense Evasion and Discovery | 02:59:44-03:18:22 (derived 02:59:44-03:18:22 (+582 / +14 ms)) | 4762 / 0 | Microsoft-Windows-PowerShell/Operational 4100: 45; Security 4658: 22; Security 5158: 13; Security 5156: 13; Security 4688: 11; Security 4656: 11; Security 4663: 11; Security 4689: 10; Microsoft-Windows-Sysmon/Operational 5: 10; Microsoft-Windows-Sysmon/Operational 18: 9; Microsoft-Windows-Sysmon/Operational 23: 6; Security 4673: 6; Microsoft-Windows-Sysmon/Operational 22: 4 | 12366 | direct |
| 5 Persistence | 03:04:16-03:04:24 (derived 03:00:37-03:20:38 (-218459 / +974550 ms)) | 13 / 33 | none | 26 | direct |
| 6 Credential Access | 03:00:37-03:05:20 (derived 03:00:37-03:04:57 (+543 / -22594 ms)) | 42 / 0 | Security 4658: 2; Security 4688: 1; Microsoft-Windows-Sysmon/Operational 5: 1; Security 4656: 1; Security 4663: 1; Security 4689: 1 | 7036 | direct |
| 7 Collection and Exfiltration | 03:05:46-03:07:15 (derived 03:05:46-03:07:15 (+288 / +102 ms)) | 8 / 1 | none | 666 | direct |
| 8 Lateral Movement | 03:00:26-03:18:22 (derived 03:00:26-03:18:22 (+826 / +14 ms)) | 325 / 0 | Security 5158: 13; Security 5156: 13; Microsoft-Windows-Sysmon/Operational 18: 9; Security 4658: 8; Security 4688: 4; Security 4656: 4; Security 4663: 4; Microsoft-Windows-Sysmon/Operational 22: 4; Microsoft-Windows-Sysmon/Operational 5: 3; Security 4673: 3; Security 4689: 3 | 1062 | direct |
| 9 Collection | 03:15:32-03:17:43 (derived 03:15:32-03:17:43 (+790 / +537 ms)) | 90 / 0 | Security 4688: 4; Security 4658: 2; Security 4673: 1; Security 4656: 1; Security 4663: 1; Security 4689: 1; Microsoft-Windows-Sysmon/Operational 5: 1; Microsoft-Windows-Sysmon/Operational 23: 1 | 1199 | direct |
| 10 Persistence Execution | 03:19:53-03:28:20 (derived 03:00:37-03:20:38 (-1155459 / -461450 ms)) | 15 / 29 | Microsoft-Windows-Sysmon/Operational 5: 1 | 356 | direct |

Steps 5 and 10 share one persistence artifact but disjoint windows; mapped anchor hits counted for both steps: 0. Their derived windows are identical because both steps derive from the same shared anchor, which also appears before the install, so the committed windows instead come from the plan sequence and the post-reboot service start. Step 5 is the install in its window: the 9 service-install and registry anchor hits are now mapped events (Windows Service Activity plus Registry Key/Value Activity) alongside the mapped Invoke-Persistence script block, and its unmapped column is empty. Step 10 is execution after the reboot: a mapped Sysmon 1 process creation of the service binary by its parent service controller inside the step-10 window, with a mapped rundll32 child seconds later, is direct evidence — step 10 is not indirect-only.

## LSASS credential access (step 6)

Sysmon 10 opens against lsass in the chain window: n = 326. By GrantedAccess (verbatim `actual_permissions`): `0x1000` 293, `0x1000000` 1, `0x101001` 2, `0x1400` 24, `0x1f3fff` 2, `0x1fffff` 3, `0x3000` 1. Dumping-grade opens (GrantedAccess in the chain file's high-access set) by ingest time:

| Ingest time (UTC) | Opens | Step windows overlapping it | Attribution |
|---|---|---|---|
| 03:05:17-03:05:17 | 2 | [3, 4, 6, 8] | step 6 evidence |
| 03:09:31 | 1 | [4, 8] | not attributed by the plan |
| 03:19:32-03:19:42 | 4 | none | not attributed by the plan |

Only the opens inside step 6's own window count as step-6 evidence (a cluster shown as overlapping no step window falls outside all of them; the late cluster ends seconds before the step-10 window opens). The rest are reported here under the step windows they fall in, labelled not attributed by the plan, never as step-6 evidence. Matching on merely touching lsass would report 326 and drown the dumping-grade opens in benign `0x1000` queries, so every LSASS check keys on GrantedAccess.

## Known visibility gaps (expected, not normalizer bugs)

- Service-based persistence (steps 5 and 10, T1543.003): Security 4697 and System 7045 now map to Windows Service Activity (201004, Create); unmapped leftovers in either bucket: 0 and 0. The pinned OCSF 1.9.0 win extension class is `windows_service_activity` (attribute `win_service`).
- Registry modification (steps 3 and 5, T1112 / T1547.001): Sysmon 12, 13 and 14 now map to Registry Key/Value Activity (201001/201002); unmapped leftovers: 0, 0 and 0. Together Sysmon 12/13 were 78692 of 196081 records, all mapped.
- Closed gap: Sysmon 7 image loads (20259) now map to Module Activity (1005, Load); unmapped leftovers in that bucket: 0. The pinned OCSF 1.9.0 core class is `module_activity` (attribute `module`).

## Recommendation: which unmapped ids to map next

1. Security 4658/4656/4690/4663 (handle and key-deletion auditing) — now the largest unmapped buckets in this dataset after Sysmon 7 was mapped to Module Activity (1005).
