# Day-2 correlate

Deterministic correlation of the declared Sigma rule findings
into incidents: counts and ids only, no event content. Produced
by `eval/correlate_census.py`; inputs are the replay store
(`data/replay`), the compact ATT&CK dictionary v20.0
(`data/attack/enterprise.json`),
`eval/apt29_day1_ground_truth.json`, and the incidents stored in
Postgres by `corvus correlate replay`. Date: 2026-10-28.

## Method

- Findings come from the declared rule set (1792 evaluated
  SigmaHQ rules; see `eval/reports/day2_replay_detect.md`).
- `corvus correlate replay` loads every replay finding, the
  referenced events, plus every Authentication event overlapping
  the findings' time range padded below by the session gap, and
  passes the session gap (30 minutes), max span (24 hours) and
  auth failure threshold (3) from `get_settings()`.
- Incidents upsert by the unique `correlation_key`; re-running
  over the same data updates the same rows, never duplicates.
- A ground-truth step is covered by an incident when the
  incident holds a finding inside the step window whose
  technique parent is one of the step's techniques (parent or
  self on both sides), counting APT29-file findings only.
- The lateral source/target hosts come from the ground truth
  (step 8); the report checks one incident holding findings
  inside the step-8 window from both, and names the join rule
  from that incident's own findings and referenced events.
- This report says events -> incidents with the declared rule
  set, not alerts -> incidents: the replay findings are atomic
  Sigma matches, not triaged SIEM alerts.

## Events -> incidents with the declared rule set

| scope | events (n) | findings (n) | incidents (n) |
| --- | --- | --- | --- |
| whole store | 798471 | 6074 | 234 |
| APT29 day-1 file | 152491 | 1483 | 3 |

## Incidents per severity floor

| floor | incidents (n) |
| --- | --- |
| 2 | 7 |
| 3 | 115 |
| 4 | 87 |
| 5 | 25 |

- factor 4 (success after failures) fired on n=1 incident(s).

## Incident size (findings per incident)

The host join key glues long single-host runs together; the
breadth bonus is provisional and calibrated later with the harness.

- max findings in one incident: n=971
- median findings per incident: n=3

| incident | hosts | findings (n) |
| --- | --- | --- |
| corr-8803c60c13b542ab | newyork | 971 |
| corr-435fc6bc75d237c9 | nashua, scranton | 511 |
| corr-e0f98e2c11bdd579 | mordordc | 423 |
| corr-02bbf5f805f93e12 | mordordc, workstation5, workstation6, workstation7 | 297 |
| corr-a59150468ab756e5 | mordordc | 273 |

## APT29 step coverage by the top incidents

Top 5 APT29-touching incidents by finding count (n=3 touch the APT29 file; n=1483 of n=1483 APT29-file findings sit in n=3 incidents).

| incident | findings (n) | steps covered (n) | steps |
| --- | --- | --- | --- |
| corr-8803c60c13b542ab | 971 | 3 | 1, 4, 9 |
| corr-435fc6bc75d237c9 | 511 | 8 | 1, 3, 4, 5, 6, 7, 8, 9 |
| corr-07cde93af04622bd | 1 | 0 | (none) |

- lateral movement goes from scranton to nashua (ground-truth hosts): n=348 findings inside the step-8 window on scranton, n=95 on nashua.
- direction verified from the PsExec/PSEXESVC/Invoke-Command-marked replay events in the window: launch activity on the source (scranton: Process Activity n=28, Script Activity n=28 including n=3 Invoke-Command script blocks, Module Activity image loads n=215, Network Activity n=5) vs service-side execution on the target (nashua: Windows Service Activity creations n=8, Process Activity starts n=61, Module Activity loads n=155, Authentication logons n=8).
- the lateral step joins scranton and nashua: one incident holds findings inside the step-8 window from both hosts.
  corr-435fc6bc75d237c9: linked by a shared human user (n=1 shared).

## Stored run vs in-memory run

- stored incidents in Postgres: n=234.
- n=0 stored incidents were not produced by this run. Re-runs never delete: keys from earlier runs (for example with different settings, which merge or split clusters differently) stay in the table, so measurements with different settings should use a fresh database.
- the stored run is identical to the in-memory run above (n=234 rows, same keys, titles and floors): the CLI loads every event the correlation reads (all referenced events plus every Authentication event in the padded range), so factor 4 and the process lineage see the same evidence either way.

- paging assumption for the Authentication context scan holds: max n=7 stored Authentication events share one millisecond (page size 200).

