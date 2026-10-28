# Day-1 replay load report

Load: `corvus replay load data` (default `data/replay/`, n = 440 files).
Window: full `data/` checkout as fetched per `datasets/README.md`, run 2026-10-27.
Analysis: the load summary plus `data/replay/provenance/*.parquet` joined to
`data/ground_truth.json` (n = 444 keys). Every store-derived count below
reproduces with `uv run python eval/replay_census.py` (fixture-tested in
`tests/test_replay_census.py`); unmapped buckets come from the load summary,
since the store keeps mapped events only. Counts and ids only below, no event
content or names.

## Load totals

- Files processed: 440. File-level parse errors: 0 (a failing file aborts
  the load; none did, and a stats-only re-scan reproduced the summary exactly).
- Runtime: 37.4 s (loader summary; 37.61 s wall). Peak memory: 475,742,208 bytes
  max RSS (~454 MiB), via `/usr/bin/time -l`.
- Mapped events: 276,787. Unmapped records: 580,235 in 388 (channel, event id)
  buckets. Unsupported archive members (non-JSON, e.g. pcap-only): 47.

## Files by dataset and label source (n = 444 ground-truth keys)

| Dataset | Label source | Keys | Loaded | Never loaded | Zero mapped |
|---|---|---|---|---|---|
| evtx-attack-samples | evtx-folder | 276 | 275 | 1 (.etl, unsupported suffix) | 82 |
| evtx-attack-samples | evtx-filename | 3 | 3 | 0 | 3 |
| security-datasets | otrf-metadata | 144 | 144 | 0 | 34 |
| security-datasets | otrf-folder | 21 | 18 | 3 (1 .cap, 2 bare .json duplicates skipped by design) | 6 |
| Total | | 444 | 440 | 4 | 125 |

Files with at least one mapped event: 315 (193 evtx-attack-samples, 122
security-datasets), matching the provenance distinct-file counts.

## Events per OCSF class (n = 276,787; parquet re-read matches exactly)

| Class | Events |
|---|---|
| 1007 Process Activity | 262,568 |
| 1001 File System Activity | 7,064 |
| 4001 Network Activity | 4,910 |
| 3002 Authentication | 1,420 |
| 1009 Script Activity | 804 |
| 1006 Scheduled Job Activity | 21 |

## Top 15 unmapped (channel, event id) buckets (n = 580,235 records)

| Channel | Event id | Records | otrf-metadata techniques co-occurring |
|---|---|---|---|
| Microsoft-Windows-Sysmon/Operational | 12 | 154,253 | 56 |
| Microsoft-Windows-Sysmon/Operational | 7 | 80,244 | 56 |
| Microsoft-Windows-Sysmon/Operational | 13 | 66,806 | 56 |
| Windows PowerShell | 800 | 44,894 | 32 |
| Microsoft-Windows-PowerShell/Operational | 4103 | 39,447 | 32 |
| Security | 4658 | 33,254 | 53 |
| Security | 4656 | 17,237 | 53 |
| Security | 4690 | 16,154 | 53 |
| Microsoft-Windows-RPC | 6 | 14,965 | 0 |
| Microsoft-Windows-RPC | 5 | 14,508 | 0 |
| Security | 4663 | 12,718 | 53 |
| Security | 5156 | 12,024 | 54 |
| Security | 5447 | 11,713 | 9 |
| Security | 5158 | 11,656 | 54 |
| Security | 4703 | 8,382 | 44 |

"Co-occurring" = the bucket occurs in at least one otrf-metadata file carrying
that technique label (n = 56 techniques, 144 files). This is co-occurrence,
not evidence: high-volume background events such as Sysmon 12/7/13 appear in
nearly every labeled file, so the column does not discriminate between
techniques and must not be read as the bucket detecting them.

## Technique and tactic coverage (mapped events)

- otrf-metadata techniques with at least one mapped event: 56 of 56.
  Techniques with none: none.
- Tactics with at least one mapped event: 9 of 9 (Collection,
  Command and Control, Credential Access, Defense Evasion, Discovery,
  Execution, Lateral Movement, Persistence, Privilege Escalation).
  Tactics with none: none.

Coverage here means the labeled file has at least one mapped event; it is not
evidence that the technique fired — the mapped events may be unrelated
background activity in the same file.

## In-band technique references (provenance flag)

- Events: 93 in 20 files.
- evtx-attack-samples: 59 events in 8 files.
- security-datasets: 34 events in 12 files.

## Recommendation: which unmapped ids to map next

A co-occurrence ranking by number of distinct otrf-metadata techniques
co-occurring with each bucket (ties by volume). Numbers are (techniques,
records). High counts partly reflect background volume, not detection power.

1. Sysmon 12 (56, 154,253) → Registry Key Activity (win extension,
   class_uid 201001, category System): CreateKey/DeleteKey to activity 1
   Create / 4 Delete with the target in `reg_key.path`. Sysmon 14 renames
   belong to the same class (activity 5 Rename, old name in `prev_reg_key`).
   Sysmon 13 (56, 66,806) → Registry Value Activity (201002): value-set to
   activity 2 Set with `reg_value.name` / `reg_value.path` and the content
   in `reg_value.data`. Class and attribute names verified against the
   v1.4.0 win extension files (`extension.json` uid 2, `registry_key_activity`
   / `registry_value_activity` events, `reg_key` / `reg_value` objects).
   Detection Finding (2004) is findings-only, never telemetry, so it is not
   a mapping target.
2. Sysmon 7 (56, 80,244) — image load → Module Activity (1005,
   category System), activity 1 Load, with the loaded image in
   `module.file` and the loading process in `actor.process`. Class and
   attribute names verified against the v1.4.0 `module_activity` event
   and `module` object files.
3. Security 5156 / 5158 (54 each, ~12k / ~11.7k) — WFP permit/block; fits 4001,
   complements Sysmon 3.
4. Security 4688 (54, 2,075) — process creation; small but broad, complements
   Sysmon 1 on hosts without Sysmon.
5. Security 4656 / 4658 / 4690 / 4663 (53 each) and 4689 (53, 1,749) —
   handle/object auditing; bulk host activity around the already-mapped events.
6. Sysmon 5 (52, 1,399) — process termination; closes the Sysmon 1 lifecycle.
7. Sysmon 9 (48, 2,936), Security 4673 (47, 2,933) — raw-access reads and
   privileged-service calls; credential-access-adjacent.
8. Security 4703 (44, 8,382), Sysmon 18 / 22 (44 each), Security 4627 / 4670 /
   4672 (43–42) — second tier by co-occurrence.

Deliberately deprioritized despite volume: classic PowerShell 800 and 4103
(32 techniques each — narrower, mostly duplicate Script Activity coverage),
RPC 5/6 (0 co-occurring otrf-metadata techniques — EVTX-only noise for attack
detection), Security 5447 (9 techniques).
