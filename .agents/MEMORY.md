# MEMORY.md — Project Corvus durable notes

> 📓 Also on purpose: this is the agent's notebook between coding sessions. Public by design, boring by rule (see rule 9 in AGENTS.md).

## Positioning

Corvus is NOT a SIEM. It plugs into the SIEM the org already runs (Wazuh in
hackathon scope): consumes alerts via `SiemAdapter`, correlates
deterministically into ATT&CK chains, reasons with AI, pushes Sigma-derived
rules back to Wazuh (shadow first, human approval).

## Non-negotiables

- Hackathon window Oct 27 - Nov 4, 2026; keep commit history honest.
- Agents never commit, amend, or push. The maintainer commits.
- Never implement anything under Roadmap in `docs/architecture.md` (rule 8).
- Raw events never leave the on-prem path; Spark sees pseudonymized
  incidents only, always through `corvus/guardrails` and the egress filter.
- Deterministic severity floor; models raise at most one level with cited
  evidence, never lower without a human.
- Datasets: OTRF, EVTX-ATTACK-SAMPLES, own lab only. Fixtures use RFC 5737
  IPs and `example.com`. Secrets from env only.

## Pointers

- Design: `docs/architecture.md`. Threat model: `docs/threat-model.md`.
- Agent rules: `AGENTS.md`. Roles: six skills under `.agents/skills/`.
- Every prompt names its role; changes under `corvus/llm`,
  `corvus/guardrails`, `corvus/learning`, `corvus/api`, `ui/` end with a
  `security-reviewer` pass.

## Session log

- 2026-10-27: created `docs/architecture.md`, `docs/threat-model.md`;
  aligned `README.md` and `AGENTS.md`; added six role skills (all
  `muse skills validate --json` clean, zero diagnostics); created this
  file. Working tree (verified): `M AGENTS.md`, `M README.md`,
  `?? .agents/`, `?? MEMORY.md`, `?? docs/`. Awaiting maintainer commit.
- 2026-10-27: added the runnable skeleton (environment-only settings,
  `/health` reporting `degraded` when the database or Glimmer is
  unreachable, SQL migrations under a Postgres advisory lock, Compose
  taking all secrets from the external env file) with tests for each
  behavior. Verified with `make lint` and `make test` (9 passed,
  including the live migration test; figures produced by those
  commands). Skeleton committed by the maintainer.
- 2026-10-28: reviewed the OCSF models against the OCSF 1.4.0 schema
  (`corvus/normalize/ocsf.py`, `docs/ocsf.md`): schema-named `actor.user`,
  `metadata.product`/`log_name`, `process.file`; year-2000 time floor with
  an epoch-seconds error; `severity_id` 99; per-endpoint entity keys; the
  network `action_id`; `OcsfEvent` as a discriminated union. Verified with
  `make lint` and the full `make test`, including the live migration test.
  Awaiting maintainer commit.
- 2026-10-28: hardened the `SiemAdapter` contract
  (`corvus/adapters/siem.py`): strict `Entity` filters that reject
  placeholders, paged `stream_alerts` resuming on `(time, uid)` with a
  per-event uid requirement, a source-grouped inventory from an explicit
  category map with an `other` fallback, a type-checked Protocol assertion
  so `make lint` fails on drift, and the `update_list` roadmap note. The
  fixture uses real telemetry source names with a shared-timestamp pair.
  Verified with `make lint` and `make test` (only the Postgres-backed
  migration test could not run here; no database reachable). Awaiting
  maintainer commit.
- 2026-10-28: added migration `0002_core_tables.sql` under
  `corvus/state/migrations/` (idempotent plain SQL, all timestamps
  `timestamptz`): checkpoints, work queue, incidents, agent steps, rules,
  dispositions, deployment-stable pseudonyms, spend, and LLM attempts.
  Incident `severity_id` stays within one level above the deterministic
  floor; `correlation_key` and queue `dedupe_key` keep re-runs after a
  crash from creating duplicates; analyst dispositions delete-restrict
  their incident and rule. Checks live in the guarded integration test
  in `tests/test_migrations.py`. Awaiting maintainer commit.
- 2026-10-28: implemented the durable work queue in
  `corvus/state/queue.py` on the existing `work_queue` table from
  migration `0002` (no new migration needed): deduped enqueue (a key
  stays taken after `done`/`dead`; a deliberate re-run needs a new
  key), `SKIP LOCKED` claim in due order, owner-only heartbeat so
  long handlers keep their lease, lease reclaim after a crash that
  counts as an attempt and ends in `dead` for poison jobs, owner-only
  complete/fail so a stale worker cannot overwrite a new owner, and
  failure backoff with jitter ending in `dead`. Handlers must be
  idempotent under at-least-once delivery. Covered by guarded
  integration tests in `tests/test_queue.py`, with the shared
  Postgres guard in `tests/conftest.py`, and verified with
  `make lint` and the full `make test`. Awaiting maintainer commit.
- 2026-10-28: added reproducible eval dataset plumbing
  (`datasets/README.md` with pinned revisions and SHA-256 checksums,
  `scripts/fetch_datasets.py`, `eval/ground_truth.py`): 279
  EVTX-ATTACK-SAMPLES samples (tactic-level labels, technique tokens
  kept when present) and 165 OTRF atomic Windows files (technique
  labels from metadata). Data lives under git-ignored `data/` only.
  Awaiting maintainer commit.
- 2026-10-28: added the Windows normalizer
  (`corvus/normalize/windows.py`, verified against the installed
  `evtx` API and probed replay files before designing the readers):
  Sysmon 1/3/11 to Process/Network/File-System Activity, Security
  4624/4625 to Authentication, Security 4698 and TaskScheduler 106 to
  Scheduled Job Activity. Readers stream `.evtx` and `.zip`/`.tar.gz`
  JSON-lines without loading archives into memory; anything else is
  counted per `(channel, event id)` and pcap-only archives are
  `unsupported`, never silent. Uids are opaque truncated hashes so
  dataset file names never enter the record, and ingestion path
  fields are stripped from `raw_data`. Replay products and channels
  added to the `SiemAdapter` source-category map; the Source column in
  `docs/ocsf.md` now names `windows.py`. Follow-up pass: channels
  match case-insensitively (canonical spelling in `log_name`),
  older (`log_name`/`event_data`) and nested (`winlog`) winlogbeat
  layouts extract by record keys, no mapper drops a field (initiating
  processes land in `actor.process`, Windows LogonType maps to the
  pinned OCSF `logon_type_id` enum with the raw value kept), and
  `iter_dataset_file` streams events with caller-owned stats while
  `read_dataset_file` stays a thin wrapper. Verified with `make lint`
  and the unit plus live-replay integration tests (per-format unknown
  share under 5% on the representative files; the full census confirms
  it on every file). Later fix: channel-less records count under the
  `System.Provider` name instead of `unknown`, and Windows LogonType
  12/13 map straight to OCSF `logon_type_id` 12/13.
- 2026-10-28: extended the Windows normalizer for the multi-stage chain:
  Sysmon 10 maps to Process Activity with activity Open (source process
  as `actor.process`, GrantedAccess verbatim in `actual_permissions`,
  CallTrace kept in `unmapped` — the pinned 1.4.0 schema has no typed
  slot for it), and PowerShell 4104 maps to the new Script Activity
  class (1009, Execute; script text, block id, PowerShell type id
  typed, message numbers in `unmapped`). Class/activity ids read from
  the `ocsf-schema` v1.4.0 tag, not from memory. Census over every
  replay file (857022 records): 259479 Sysmon 10 and 804 script-block
  records newly map, zero leftovers in either bucket, everything else
  unchanged. Awaiting maintainer commit.
- 2026-10-27: added the replay adapter (`corvus/adapters/replay/`,
  DuckDB over Parquet under `data/replay/`): `corvus replay load`
  streams dataset files (including bare JSON-lines) in batches
  through the Windows normalizer into per-file events/provenance
  tables with explicit schemas, written atomically; dataset paths
  and an in-band-technique flag live only in provenance (keyed by
  event uid, joined to ground-truth keys by the harness), never in
  returned records. In-band references (`corvus/normalize/technique_ids.py`,
  id tokens and `technique_name=` values) stay verbatim in evidence
  and are masked only at later model-call time. The adapter meets
  the `SiemAdapter` contract (same parametrized behavior suite as
  the fake; rule methods stay read-only until alert generation).
  Verified with `make lint` and `make test`. Awaiting maintainer
  commit.
- 2026-10-27: replay validation fixes. Masking a `technique_name=`
  value also stops at a backslash, so masked serialized JSON still
  parses (an escaped quote or `\r\n` escape no longer lets the value
  eat following fields); new `mask_payload` masks string leaves of
  structured payloads for the model-call layer instead. Directory
  loads skip bare JSON-lines files (some payloads ship zipped and
  bare byte-identical while metadata links only the archive; an
  explicitly named file still loads). OTRF files no metadata file
  links carry the new `otrf-folder` ground-truth source (tactic
  only). Verified with `make lint` and `make test`. Awaiting
  maintainer commit.
- 2026-10-27: ran `corvus replay load data` over the fetched datasets
  (440 of 444 ground-truth files loaded; 4 skipped by suffix policy,
  125 loaded with zero mapped events) and saved the counts-only census
  as `eval/reports/day1_replay_load.md` (per-class totals, top unmapped
  buckets, full file-level coverage, in-band counts, co-occurrence
  ranking led by Sysmon 12/13/7; registry target corrected to the win
  extension classes 201001/201002). Counts reproduce with
  `uv run python eval/replay_census.py` (fixture-tested).
  Awaiting maintainer commit.
- 2026-10-27: validation pass on the day-1 report, recorded here.
  Registry targets verified against the upstream v1.4.0 win extension
  files (201001/201002 with `reg_key`/`reg_value` attributes; 2004 is
  findings-only). Reach relabeled as file-level co-occurrence in both
  places, run date fixed. `ruff check`, `ruff format --check`, and
  `mypy` green via the venv binaries (`uv` cache unwritable in this
  sandbox); `pytest` 143 passed with only the Postgres-guarded tests
  failing (no database reachable). Awaiting maintainer commit.
- 2026-10-27: fixed report recommendation 2 (Sysmon 7 image load goes
  to Module Activity 1005, activity 1 Load, not 1007; class and
  `module.file` verified against the v1.4.0 `module_activity` event and
  `module` object files) and changed the census usage to
  `uv run python eval/replay_census.py` in the module and the report.
  `ruff check` and `ruff format --check` green on the changed files.
  Awaiting maintainer commit.
- 2026-10-28: Day-1 review lessons folded into `AGENTS.md` and the role skills
  under `.agents/skills/`.
- 2026-10-28: mapped the last two win-extension classes
  (`corvus/normalize/windows.py`, `corvus/normalize/ocsf.py`):
  Sysmon 12/14 to Registry Key Activity (201001, Create/Delete/Rename)
  and Sysmon 13 to Registry Value Activity (201002, Set), Security
  4697 and System 7045 to Windows Service Activity (201004, Create);
  Sysmon 7 stays unmapped and counted. Day-1 census (196081 records):
  registry and service events newly map (per-activity counts
  corrected in the next entry); steps 3 and 5 keep `direct` with
  registry/service anchors in mapped events, and
  `eval/reports/apt29_day1_replay_load.md` was regenerated from the
  census. Verified with the lint gate and the full suite (only the
  Postgres-guarded tests failing, no database reachable). Awaiting
  maintainer commit.
- 2026-10-28: review fixes on that mapping. Flat NXLog records carry
  `EventType` INFO (the severity), so the Sysmon 12 op is read from
  the `Message` `EventType:` line, falling back to Create; Sysmon 12
  DeleteValue is a Registry Value Activity Delete, not a key record.
  Day-1 per-activity counts: key Create 60094 / Delete 876, value Set
  17541 / Delete 181, all reported in the regenerated day-1 report.
  Verified with the lint gate and the full suite (only the
  Postgres-guarded tests failing, no database reachable). Awaiting
  maintainer commit.
- 2026-10-28: moved the pinned OCSF schema from 1.4.0 to 1.9.0
  (`ocsf-schema` tag `1.9.0`; `OCSF_SCHEMA_VERSION` is `1.9.0`) and
  mapped Sysmon 7 to Module Activity (1005, Load). Verified every
  modelled class, activity, enum and attribute against the 1.9.0
  files: no used class uid or enum value changed (only additions).
  `job.cmd_line` (deprecated in 1.9.0) is gone from the `Job` model;
  the 4698 task-XML command lives in `job.job_actions[].cmd_line`
  and the anchor search covers it. Win extension classes declare
  `metadata.extensions` (win, uid 2, version 1.9.0). Day-1 census
  (196081 records): 20259 Sysmon 7 events newly map (zero
  leftovers), all 10 step verdicts stay `direct`, no ground-truth
  change. Verified with the lint gate and the full suite (only the
  Postgres-guarded tests failing, no database reachable). Awaiting
  maintainer commit.
- 2026-10-28: review fixes on that change, all verified against the
  pinned 1.9.0 files. `Extension.uid` is the string `"2"`
  (`_entity.uid` is `string_t`); hashes are the `Fingerprint` object
  with required `algorithm_id` (MD5 1, SHA-1 2, SHA-256 3, Imphash
  18, else 99 keeping the source name); 4698 actions carry type 2
  `Execute`. Anchor search now includes module file fields: step 8
  keeps 4 PSEXESVC.exe hits whose anchor is only in the typed file
  description/product, all 10 verdicts stay `direct`. Day-1 load
  cost, same file and machine: 13.5 s / 71165022 bytes before
  (`5d2296d`), 16.2 s / 92128495 bytes after (+20259 events).
  Verified with the lint gate and the full suite (178 passed; only
  the Postgres-guarded tests failing, no database reachable).
  Awaiting maintainer commit.
- 2026-10-28: fixed the `serialize_ocsf` docstring carry-over from the
  9L review (typed `None` fields are dropped at every nesting level,
  but the free-form `unmapped` object keeps nulls verbatim as logged)
  and built deterministic correlation as pure logic in
  `corvus/correlate/` (no storage, CLI, or report; the follow-up adds
  those). Findings join on host, user (service identities never join),
  endpoint IPs, and host-scoped process lineage within a 30-minute
  session gap and a 24-hour max span (defaults in `corvus/settings.py`
  with comments); cross-host joins need a shared human user or a
  remote-IP-to-device-IP lateral link. The severity floor (1-5, never
  6) scores factors 1, 2, and 4 with per-factor explanations in
  `severity_factors`; every incident field matches the `incidents`
  table of migration `0002` plus that column. Fix pass: merges keep
  the oldest cluster's key (no string comparison), breadth counts
  distinct per-finding primary tactics (one multi-tactic finding earns
  no bonus), factor 4 scans every matching Authentication event in the
  passed map inside `[first_seen - session gap, last_seen]`, and the
  score step is the named `SCORE_BREADTH_STEP`. Covered by 23 tests in
  `tests/test_correlate.py`; census over the replay store (6074
  findings) yields 234 incidents with floors 2:7, 3:115, 4:87, 5:25,
  58 at breadth >= 3, and 1 firing factor 4. Verified with `make lint`
  (green) and the full `make test` (294 passed with Postgres).
  Awaiting maintainer commit.
- 2026-10-28: platform pin refresh (every pin re-checked against its
  upstream release list on 2026-10-28). Python 3.12 -> 3.14
  (`requires-python`, ruff target, mypy, `python:3.14-slim` base; 3.15
  exists but locked duckdb 2.0.0 ships no cp315 wheel, recorded in the
  Dockerfile). Postgres image 16 -> 18 (volume now at
  `/var/lib/postgresql` per the official image docs; README notes the
  dev volume must be recreated, pre-release with no data to migrate).
  gitleaks hook v8.28.0 -> v8.30.1 (ruff-pre-commit v0.17.3 and uv
  0.13.6 already latest). `uv lock --upgrade` (pydantic-settings
  2.16.1 -> 2.16.2, plus mypy, platformdirs, python-discovery, tzdata
  and virtualenv bumps). MITRE attack-arsenal pin -> `201db70`
  (Day-1 README byte-identical at both commits; the 14 in-between
  commits touch only CALDERA_DIY, the APT29 PDF, Day 2 and the APT29
  README). `httpx` -> `httpx2` 2.16.0 (BSD-3-Clause, noted in README;
  Starlette deprecation warning gone from pytest output). Pinning rule
  added to AGENTS.md conventions. Migration test now expects
  `RestrictViolation` on PG18 (constraint is ON DELETE RESTRICT; no
  code under `corvus/` depends on the SQLSTATE). Ruff 0.17.3 with
  target py314 drops redundant `except` parens (valid 3.14-only
  syntax, identical semantics verified at runtime); applied to 2
  files to keep the lint gate green. Maintainer review ran the full
  suite on Postgres 18.6 from docker-compose.yml: 188 passed, no
  warnings. Working tree: 15 files changed. Awaiting maintainer commit.
- 2026-10-28: added the MITRE ATT&CK v20.0 dictionary
  (`corvus/attack/`, exact-key lookups plus `resolve` through
  `revoked-by`; `mitre/cti` pinned at `50be388e`, fetched with
  checksums into git-ignored `data/`). 867 techniques (149 revoked)
  across 15 tactics in matrix order; v20 splits Defense Evasion into
  `stealth` and `defense-impairment`. `corvus attack build` writes the
  compact `data/attack/enterprise.json` once (0.1 s, ~220 KB) and the
  49 MB bundle is never parsed per request. NOTICE carries the
  verbatim ATT&CK section of the pinned `LICENSE.txt`. Every
  ground-truth id resolves to a live technique (no JSON change), and
  16 revoked sub-techniques have no parent because the bundle drops
  their `subtechnique-of` relationships (by design, the parent is
  never guessed). Verified with `make lint` and the full `make test`.
  Awaiting maintainer commit.
- 2026-10-28: added the atomic SigmaHQ detection layer over OCSF
  events (`corvus/detect/`, reusable by `ReplayAdapter` and future
  rule backtesting): pinned SigmaHQ release, windows rules at status
  stable and test, pySigma conversion to DuckDB (ILIKE for
  case-insensitive `LIKE`, per-rule regex validation), one Detection
  Finding 2004 per rule match with deterministic uids, atomic
  per-slug finding writes plus `corvus replay detect`, and
  `eval/reports/day2_replay_detect.md` from `eval/detect_census.py`.
  Maintainer review then fixed the fidelity items from the first
  version: stock Sigma `NOT` semantics with nulled placeholders
  re-read from the raw record (report carries the per-rule old-vs-new
  delta; 4 of 1792 evaluated rules change, all gains, each verified
  against the rule and the rows); tactic `uid` as the `TA####`
  external id with the dictionary rebuilt from the pinned bundle;
  finding context in one top-level `evidences` entry per matched event
  (verified against the pinned 1.9.0 schema, not `finding_info`; the
  2004 finding itself carries no actor or endpoints); tactic-only
  attacks dropped when a technique entry covers their tactic; vendor
  `Ekos Cyber Labs`; the six previously-gained SMB-logon matches were
  excluded again as the rule intends. Verified with `make lint`
  (green) and the full `make test` (244 passed with Postgres on the
  maintainer's machine). Awaiting maintainer commit.
- 2026-10-28: added the automated OCSF conformance test. Pinned
  schema source fetched with `scripts/fetch_datasets.py`
  (`ocsf/ocsf-schema` tag `1.9.0`, commit `856d462b…`, only
  `categories.json`, `dictionary.json`, `LICENSE`, `events/`,
  `objects/`, `profiles/`, `extensions/windows/`, checksummed under
  git-ignored `data/`, never committed); OCSF attribution added to
  `NOTICE`. `corvus/normalize/conformance.py` resolves classes and
  objects as the schema defines them and checks required presence,
  known names (flagged even when null), `*_id` enums and
  string-vs-integer types at every nesting level;
  `tests/test_conformance.py` runs it over every normalizer fixture,
  Sigma-engine findings end to end, a deterministic per-class sample
  spread across all replay files, and hand-written broken records
  with precise messages. One shared `serialize_ocsf` writes the store
  JSON (no Nones, no `entity_keys`), used by both row builders and
  checked exactly by the tests. Mapper fixes from the check:
  `entity_keys` as store columns plus recompute on read;
  `actual_permissions`, `Device.type_id`, `File.type_id` as schema
  integers with hex bridging for Sigma and the chain census; required
  `Authentication.user`; `script_content` as the `long_string`
  object; always-emitted required containers; records missing a
  required attribute counted unmapped; 310 script texts recovered
  from Message/Data layouts. Eval delta: the null-semantics 4-rule
  delta is unchanged (LSASS +33 preserved via the hex bridge);
  findings 5780 to 6074 on the refreshed store; day-1 load totals
  reproduce exactly (152,491 mapped, 43,590 unmapped). Lessons folded
  into `AGENTS.md` and the matching role skills; the two 2026-10-28
  SigmaHQ entries merged into one. Verified with `make lint` (green)
  and the full `make test` (269 passed with Postgres). Awaiting
  maintainer commit.
- 2026-10-28: stored deterministic incidents in Postgres and measured
  them over the replay store (`corvus correlate replay`, migration
  `0003_severity_factors.sql`, `corvus/state/incidents.py`,
  `corvus/correlate/replay.py`). The CLI loads every replay finding,
  the referenced events plus Authentication events in the padded
  window through the replay store, and passes the session gap, max
  span and failure threshold from `get_settings()`; re-runs upsert by
  `correlation_key` with no duplicates. Census
  (`eval/correlate_census.py`, `eval/reports/day2_correlate.md`,
  counts only): 798471 events -> 6074 findings -> 234 incidents
  (floors 2:7, 3:115, 4:87, 5:25; factor 4 fires once); the APT29
  day-1 file contributes 152491 events -> 1483 findings -> 3
  incidents; max 971 / median 3 findings per incident. The two chain
  incidents cover 3 and 8 of the 10 ground-truth steps; the lateral
  step stays split across two incidents. Stored run identical to the
  in-memory run (n=234). Verified with `make lint` and the full
  `make test` (296 passed with Postgres). Awaiting maintainer commit.
- 2026-10-28: fix pass on the correlation storage and report. The
  step-8 lateral conclusion ranked hosts inside the wide window, so
  step 8 of `eval/apt29_day1_ground_truth.json` now names the
  lateral source/target hosts, verified from
  PsExec/PSEXESVC/Invoke-Command-marked replay events by class and
  count, and `eval/correlate_census.py` reads them from the ground
  truth and names the join rule from the incident's own findings and
  referenced events (a shared human user). `upsert_incidents` keeps a
  stored `severity_id` still within the new [floor, floor+1] on
  conflict and resets to the new floor otherwise; a new Postgres
  test pins both halves (it fails on the old SQL). `corvus correlate
  replay` prints how many stored incidents the run did not produce,
  and the report plus the CLI help say measurements with different
  settings need a fresh database. Verified with `make lint` and the
  full `make test` (297 passed with Postgres). Awaiting maintainer
  commit.
- 2026-10-28: built the two eval inputs for the next harness prompt
  (no harness itself). `eval/benign_windows.py` generates a declared
  synthetic benign Windows set (flat NXLog records in a `.zip` under
  git-ignored `data/benign/`, default 4 hosts and 24 h from
  2024-05-02, fixed seed, byte-stable bundle via a fixed zip member
  timestamp, per-host counts scaling with `--hours` as a per-hour
  rate): interactive/service logons, typo failures with no success
  after, benign admin processes, update tasks, installer registry
  writes including legitimate Run keys, benign PowerShell, `0x1000`
  lsass queries. The first run tripped two rules on invented record
  shapes (explorer-parented svchost, ConsoleHost-only module-logging
  context); both were corrected to the real benign shapes with the
  reasons documented in the script. Measured (seed 7): n=312 records
  at 24 h and n=108 at 6 h; replay load maps all 312 with zero
  unmapped and zero in-band; `corvus replay detect` gives 4 findings,
  all medium from the Autorun-keys rule on the documented installer
  Run keys; `corvus correlate replay` gives 4 incidents, all floor 3,
  factor 4 silent, none Critical. `eval/train_test_split.py` splits
  OTRF *recordings* (host/network siblings collapsed) per technique
  by hash rank: 55 techniques, 18 testable, 37 untestable (fewer than
  2 recordings, including purge-emptied test sides); `T0000` excluded
  and reported (2 files); multi-label files disclosed; zero test
  recordings trained anywhere, verified on the real ground truth.
  Small fixes alongside: relative `--out` resolves against the cwd,
  and `corvus replay load` of a missing path exits 2 with a clear
  error. Covered by the tests in `tests/test_benign_windows.py`,
  `tests/test_train_test_split.py` and `tests/test_replay.py`.
  Verified with `make lint` (green) and the full `make test` (316
  passed with Postgres). Compose Postgres left running. Awaiting
  maintainer commit.
- 2026-10-28: built the eval harness (`eval/harness.py`, `corvus eval
  run`): load inventory plus the product detect (`load_rules`,
  `evaluate`, `write_findings`) and correlate (`correlate_replay_store`)
  calls over the replay store, then the benign pipeline (generate,
  load, detect, correlate on a fresh git-ignored store) and the
  metric joins, writing `eval/reports/latest.md` and `latest.json`
  (every number with n, window, producing command and git commit).
  Metrics: benign false positives by severity (gate: zero Critical+);
  chain step coverage per step for the best incident and all incidents
  (APT29 day-1: 8/10 both; steps 2 and 10 have in-window findings but
  no technique match, so detection gaps, not correlation gaps);
  atomic OTRF-metadata coverage (110 files in store, 90 with a
  finding, 53 with a technique match); compression per dataset
  (whole store 798471 events -> 6074 findings -> 234 incidents);
  in-band technique ids (130 events) and the train/test split record
  (55 techniques, 18 testable). Anti-leakage runs every time (dataset,
  file and window markers everywhere; technique ids outside
  loader-flagged rows and scrubbed detector output; anchors only on
  the synthetic benign probe, since anchors are legitimate evidence
  in the attack store) and fails the run. Deltas compare against the
  committed `latest.json` via its git HEAD version (inputs differing
  voids the delta); with no committed baseline the report says so.
  Two interim bugs were fixed before finishing (uid/file join used
  finding uids instead of related event uids; row-level in-band
  exemption). Measured: 325 s wall (detect 135 s, correlate 6 s,
  leakage scan 118 s). Covered by `tests/test_eval_harness.py`
  (benign gate trips on synthetic Critical, leakage trips on planted
  strings, baseline provenance). Verified with `make lint` (green)
  and the full `make test` (327 passed with Postgres). Compose
  Postgres left running. Awaiting maintainer commit.
- 2026-10-28: fixed four review findings on the eval harness, no
  measure changed: shared leakage assertions live in
  `eval/leakage.py` (`scan_dumps`), called by `tests/test_replay.py`,
  `tests/test_chain_ground_truth.py` and the `corvus eval run` gate;
  atomic coverage now splits `with_match_n` into exact
  (sub-technique to sub-technique, technique to technique) and
  parent-only, with a per-file match column; every chain step carries
  in-window findings n plus whether any matches a step technique
  (APT29 day-1 steps 2 and 10 uncovered with n=850 and n=44
  in-window findings, none technique-match); the report meta records
  a dirty-tree flag plus changed-path count (latest.* excluded).
  Regenerated once: 6074 findings, 234 incidents, chain 8/10 best
  and all, 4 benign Medium incidents, atomic 53 = 46 exact +
  7 parent-only, both gates pass, deltas all +0 vs the committed
  baseline, 254 s wall. `tests/test_eval_harness.py` grew by the
  shared-planted-string test, the exact/parent-only/unmatched trio,
  the chain gap test and a temp-repo dirty-tree test. Verified with
  `make lint` (green) and the full `make test` (332 passed with
  Postgres). Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-10-28: fixed the atomic exact/parent-only misclassification in
  `eval/harness.py`: exact now matches at the ground truth's own
  granularity (stated technique equals a ground-truth technique, or a
  sub-technique of a parent ground-truth technique), so parent-GT
  files matching via the parent or a sub-technique are exact, not
  parent-only. The now-unused `stated_techniques` row field is gone;
  nothing else changed. Regenerated once: 6074 findings,
  234 incidents, chain 8/10 best and all, 4 benign Medium incidents,
  atomic 53 = 48 exact + 5 parent-only (was 46 + 7), both gates pass,
  deltas all +0 vs the committed baseline, 319 s wall. The
  exact/parent-only test gained the two parent-GT fixtures (finding
  states the parent; finding states a sub-technique). Verified with
  `make lint` (green) and the full `make test` (332 passed with
  Postgres). Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-10-29: added the read-only Wazuh adapter
  (`corvus/adapters/wazuh/`, checkpoints in
  `corvus/state/checkpoints.py`) and the Wazuh normalizer
  (`corvus/normalize/wazuh.py`) with 7 hand-written fixtures under
  `tests/fixtures/wazuh/` (one per mapped decoder plus an unknown
  decoder and an archive doc). Alerts page with point in time plus
  `search_after` on the stable sort `[timestamp, id]`, re-read a 120 s
  overlap window behind the cursor dropping already-seen ids, and
  persist the cursor in `checkpoints`; archives serve entity and
  time-window queries; rule translation and deployment stay
  `NotImplementedError` for the later shadow-deployment milestone.
  TLS is always verified through a CA-bundle setting (the old off
  flag is removed from settings and the env example). The OCSF models
  gained two schema-defined optional fields the mapper needs
  (`Analytic.category`, `Process.user`); the shared category fallback
  now counts absent classes as zero instead of raising. Verified with
  `make lint` (green) and the full `make test` (376 passed with
  Postgres). Eval harness re-run to throwaway reports: every metric
  delta +0 vs the committed baseline, both gates pass, 237 s wall.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-29: fixed six live-review defects in the Wazuh adapter and
  normalizer. The resume floor dropped late-indexed alerts, so the
  cursor now carries a seen set of window `(time, uid)` pairs and only
  seen uids are skipped; decoder names now match the live indexer
  (auditd SYSCALL only with unset-auid fallback, three syscheck
  decoders) with 8 live-shape fixtures; TLS uses a context clearing
  only the strict flag a stock root CA trips, with localhost tests for
  connect, unknown CA, and hostname mismatch; sorting is
  `[timestamp, _id]` with archive event uids from the document `_id`;
  the endpoint allowlist is a strict index regex; inventory aggregates
  archives with an alerts decoder check for class 2004. Fixed along
  the way: one reworked test expected the wrong unmapped key until
  archive samples stopped carrying a rule block. Verified with
  `make lint` (green) and the full `make test` (387 passed with
  Postgres). Eval harness re-run to throwaway reports: every metric
  delta +0 vs the committed baseline, both gates pass, 237 s wall.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-29: built the LLM foundations every model call will use (no
  model calls yet): per-purpose backend config in `corvus/llm/config.py`
  (triage/analysis purposes, MODEL_PROFILE routing, secret redaction),
  the static price book in `config/price_book.yaml` plus
  `corvus/llm/price_book.py` (PyYAML declared explicitly in
  `pyproject.toml`; 6.0.3 confirmed latest stable on 2026-10-29),
  migration `0004_llm_audit.sql` (audit-only `llm_attempts.reasoning`,
  `token_source`, `incident_analyses`, `spend_reservations`), and the
  Postgres-backed spend/budget guard in `corvus/llm/spend.py`
  (pre-call reservations under an advisory lock, expiring holds, local
  spend at 0). One self-authored budget assertion had the wrong
  threshold (fixed; the code was right). Verified with `make lint`
  (green) and the full `make test` (417 passed with Postgres). No
  normalizer, correlation, prompt or model changes, so no eval delta.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-29: small three-part fix on the LLM foundations, nothing else
  changed. Startup now requires a price-book row for every configured
  model (`corvus/llm/config.py`, `PRICE_BOOK_PATH` override for tests;
  no implicit zero for on-prem) and refuses on-prem trust on a public
  endpoint unless `<PURPOSE>_ALLOW_PUBLIC_ONPREM=1` (stub-injected
  resolver in tests, short-timeout getaddrinfo in production).
  `convert_reservation` in `corvus/llm/spend.py` always records the
  spend and returns a `ConversionResult` with `hold_active`; new
  `hold_ttl` helper derives the hold from timeout x attempts plus
  margin (600 s stays the fallback). One architecture sentence added
  (reserve before, convert after). Lint nits (line length, format,
  one mypy arg-type) found and fixed before the test runs; no test
  failures. Verified with `make lint` (green) and the full `make test`
  (427 passed with Postgres). No eval delta. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-29: added the single-attempt LLM transport
  (`corvus/llm/transport.py`, `corvus/llm/attempts.py`, no validators
  or retry loop yet). One attempt over httpx2 returns content,
  reasoning, finish reason, typed tool calls, exact token counts with
  source, latency and status; Glimmer token ids split on channel
  headers (reasoning 267, answer 88, overhead 10 on the recorded ok
  reply) with detokenize caching and an estimated fallback; errors use
  the recorded Meta shape; retries only on 429/5xx; secrets never in
  errors. `record_attempt` writes the attempt row plus the billed
  spend row in one transaction. 32 new tests (recorded fixtures,
  derived reasoning-only case, stub server, injected clock). One new
  assertion expected unrounded spend (fixed; the code was right).
  Verified with `make lint` (green) and the full `make test` (460
  passed with Postgres). No eval delta. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-29: routed LLM spend through the reservation exactly once
  (`corvus/llm/spend.py` gains a `conn` parameter on `record_spend`
  and `convert_reservation`; `corvus/llm/attempts.py` takes
  `reservation_id` and converts inside the attempt transaction).
  Channel split now keys on the `=self`/`=user` marker, the header
  cache keys on root plus model, latency starts after the limiter
  slot, and attempt errors accept strings or string-keyed mappings.
  10 new tests (double conversion, rollback keeps the hold, derived
  marker case, per-root cache, injected-clock latency). One new test
  passed `reservation_id` twice (fixed; the code was right).
  Verified with `make lint` (green) and the full `make test` (470
  passed with Postgres). No eval delta. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-29: built `corvus/guardrails/` payload preparation
  (`payload.py`: always-on structured `mask_payload`, `visible`
  detector labels wrapped under `detector_labels`, `blind` stripping
  attacks/rule tags/`technique_name` values, `DETECTOR_LABELS`
  default, rule titles untouched; cloud adds pseudonyms plus secret
  redaction, on-prem skips both), the stable pseudonymizer
  (`pseudonymizer.py`: per-kind Postgres counters HOST/USER/IP/DOMAIN/
  EMAIL-0001, advisory-locked race-safe get-or-create, adapter
  canonicalization, longest-first free-text replacement with the
  documented boundary rule plus multi-label host suffix), and the
  egress filter (`egress.py`: exact-host allowlist with one-level
  `*.` wildcard, 443-unless-named port, no userinfo, secret redactor
  with 20/20 corpus). `run_attempt` checks every cloud URL before
  sending (allowlist from model endpoints plus `WAZUH_INDEXER_URL`).
  46 new tests; the two existing cloud transport tests now inject a
  stub-scoped filter. Failures found and fixed first: mid-pattern
  regex flag, JSON quoted-key redaction, short-bearer over-match,
  lax allowlist entry parsing, cross-call FQDN leak, one test-side
  tags nesting error, one fixture eaten by the tag mask. Verified
  with `make lint` (green: ruff check, format, mypy on 52 files) and
  the full `make test` (540 passed with Postgres). No normalizer,
  correlation, prompt or model changes, so no eval delta. Compose
  Postgres left running. Awaiting maintainer commit.
- 2026-10-29: closed the free-text and credential gaps in
  `corvus/guardrails/` (URL checks untouched). Cloud payloads drop
  every `raw_data` field; a deterministic scanner finds IPs,
  e-mails, FQDNs, UNC/`DOMAIN\user` spans, profile/home owners and
  command user arguments in any string field, with longest-span
  overlap resolution; `register()` plus the new `entities` argument
  carry typed entities across events; an FQDN whose short host is
  known keeps the host pseudonym. The redactor gained 8 forms
  (`=`-style auth headers, curl user pairs, `net use` trailing
  passwords, cookies, SecureString literals, hash keywords, segment
  key matching) with 4 new safe strings. 10 new test functions
  including the 17-string acceptance event and 10 more leak events
  (540 to 550 passed). Failures found
  and fixed first: 4 prior tests superseded by the scanner (2
  updated to the new intended behavior, 2 kept via the known-host
  alias), `=`-auth needing no space, test-count assertions. Verified
  with `make lint` (green: ruff check, format, mypy on 52 files) and
  the full `make test` (550 passed with Postgres). No normalizer,
  correlation, prompt or model changes, so no eval delta. Compose
  Postgres left running. Awaiting maintainer commit.
- 2026-10-29: added the deterministic prompt-injection signal
  (`corvus/guardrails/injection.py`, security-reviewer): 16
  documented patterns in 4 families (instruction override, role
  reassignment, verdict steering, exfiltration requests) with stable
  ids, examples, and suppress/inflate/exfiltrate/other effects, over
  normalized attacker-controlled OCSF fields (Unicode NFKC, case
  folding, zero-width/bidi removal, separator collapsing; spans refer
  to normalized text), plus the echo predicate for the future
  validator 5 and idempotent `scan_incident` (migration
  `0005_injection_signals.sql`: `incident_signals`,
  `security_events`, `incidents.review_required`; signals never move
  the severity floor). Corpus: 31 injected strings flagged (every
  pattern, several case/spacing/separator/zero-width/punctuation
  encodings, imperative severity-to-info), benign strings clean;
  rescans persist once; obeying outputs
  flagged, quoted and honest outputs clean. Review follow-up fixed
  two defects the synthetic set could not see: `raw_data` JSON
  envelopes are walked leaf by leaf with mapped-field dedupe (keys
  never scanned), and flat matches must be token-aligned in the
  collapsed text; `informational`/`info` dropped from
  `steer.severity_low` on measured telemetry (routine PowerShell and
  Sysmon severity metadata). Real-data census
  (`eval/injection_census.py`, every 20th event, n=40151 over the
  attack and benign stores): 30935 signals on 27125 events before
  (30926 severity_low from the envelopes, 9 act_as), 0 signals on 0
  events after; act_as/you_are_now need no further tightening.
  Second round: flat boundary relaxed to non-alphanumeric neighbours
  (quoted/parenthesized payloads realign, in-word matches still
  rejected); imperative "set severity to info|informational"
  restored, bare form stays out; census still 0 on 0 at n=40151.
  Corpus now 33 benign strings (react/assets, nowhere, severity 10,
  whenever reported, Severity = Informational), all clean. Synthetic
  benign set
  (`eval/benign_windows.py`, seed 7): n=312, 0 false positives (rate
  0.0). Honesty note (signal, not defence; no "detects all" claim)
  in the module docstring and `docs/threat-model.md`. Verified with
  `make lint` (green) and the full `make test` (575 passed with
  Postgres). No normalizer, correlation, prompt or model changes, so
  no eval delta. Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-10-29: built the single model entry point `corvus/llm/call.py`
  (llm-engineer, security-reviewer pass included): budget reservation
  first (over-cap refuses `pending_ai` before any contact), then
  `prepare_payload` per trust, egress pre-check for cloud, transport,
  validators 1-5 in order (syntax `invalid_output`/`truncated`,
  schema with unknown-field rejection, semantics for uids/techniques/
  pseudonyms/language, policy floor/cap/cited-escalation with missing
  floor an error, security via `echoes_injection` quarantining once
  with a `security_events` row and `review_required`, never retried),
  3-try self-correction (structured-error repeat, attempt-3
  temperature 0 plus one reasoning step up plus simplified schema,
  early stop on a repeated code), profile fallback, deterministic
  `ai_failed`, all-empty `indeterminate` (value None, escalated).
  On-prem reasoning stored in `llm_attempts.reasoning`, cloud stores
  NULL; every answer recorded with exact tokens; spend only via the
  reservation conversion. `corvus/llm/stats.py` adds pure per-model
  per-purpose metrics (calls, first-pass rate, average attempts,
  failure rate, tokens/USD per resolved call, n on every number).
  21 new stub-transport tests in `tests/test_llm_call.py`. Failures
  found and fixed first: indeterminate rule compared error codes
  instead of validator names (2 tests red), one test-side dataclass
  subscript, two mypy errors (`**dict` unpack, error-var redef).
  Verified with `make lint` (green: ruff check, format, mypy on 55
  files) and the full `make test` (596 passed with Postgres). No
  normalizer, correlation, prompt or model changes, so no eval delta.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-29: fix round on `corvus/llm/call.py` (one budget defect,
  four smaller ones; 10 new tests, 31 in `tests/test_llm_call.py`).
  Budget holds are now per transport try (worst case of one
  attempt): at most one live hold per in-flight try, conversion
  through that try's `record_attempt`, release when a try yields no
  answer; a mid-loop refusal stops the loop and ends `ai_failed`
  with `budget_exceeded` (`pending_ai` only when nothing was sent).
  Validator 5 cannot run silently off: stored signals with empty
  context signals raise `ValueError` before any reservation.
  `ai_failed` now escalates `review_required` like `indeterminate`.
  Dictionary-load and `simplified()` failures propagate instead of
  blaming the model. Hygiene: ASCII `egress` naming, filter-build
  failures release and return fatal (no escape with a live hold),
  release failures log call/reservation ids without secrets. Two
  red tests during the round (simplified-schema third scripts,
  instance `__call__` never intercepts) fixed test-side; one
  pre-commit hiccup (Go cache outside the sandbox) fixed with
  redirected caches. Verified with `make lint` (green), the full
  `make test` (606 passed with Postgres) and `pre-commit run
  gitleaks --all-files` (Passed). No eval delta. Compose Postgres
  left running. Awaiting maintainer commit.
- 2026-10-29: built the Glimmer triage queue (llm-engineer, with a
  security-reviewer pass). Failures first: the
  `test_only_call_module_drives_transport` invariant tripped because
  the worker named the `call_model` test seam, so the seam was
  removed from the worker and tests fake at the HTTP boundary
  instead; review also caught the incident header rendering
  technique ids as masked placeholders, so it now carries a count
  only. New: `CondensedIncident` in `corvus/llm/schemas.py`
  (bounded fields, entity-must-appear-in-evidence hook),
  `corvus/llm/prompts/triage.py` (stable cache prefix with the D23
  nudge verbatim, data-absent fences, deterministic
  findings-first evidence selection with stated omitted counts),
  `corvus/llm/triage_worker.py` (queue jobs, lease/3 heartbeats,
  idempotent `incident_analyses` upserts, indeterminate/unprocessed
  escalated never benign, SIGTERM drains in-flight) plus `corvus
  triage enqueue` / `run --limit N --purpose triage`; validator 5
  wired via `scan_incident` and a new no-DB `scan_events` helper
  (echoing outputs quarantine). Verified with `make lint` (green:
  ruff check, format, mypy) and the full `make test` (630 passed
  with Postgres, including 24 triage tests). Eval harness re-run to
  throwaway reports: every metric delta +0 vs the committed
  baseline, both gates pass, 244.8 s wall. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-29: fix round on the triage queue (review probes
  reproduced first, then fixed). Failures first: the two lease
  probes failed as reported (queued claims burned their leases);
  grounding rejected honest Windows paths (JSON escaping); the
  loader peaked near 2.5 GB on the real store. Fixed:
  claim-on-demand worker threads with heartbeat-first/finally in
  `process_job`, string-leaf grounding (keys never evidence),
  resolved short-circuit plus a no-downgrade upsert `WHERE`,
  row-group pushdown in the evidence loader, and fail-with-backoff
  plus type-only heartbeat warnings so no job orphans. Measured on
  the real store for the same 46-uid call: old logic 1.66 s wall /
  2.36 GiB peak RSS vs new 0.28 s / 370 MiB (both labelled
  measured, interpreter included). Verified with `make lint`
  (green), the full `make test` (640 passed with Postgres,
  including 34 triage tests) and `pre-commit run gitleaks
  --all-files` (Passed; Go caches redirected outside the sandbox).
  No eval delta (detect/correlate untouched). Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-29: fix round 2 on triage (live APT29 run overflowed the
  context: 28.5k-token prompt on a 32k window). Failures first: the
  new probe tests failed as reported until the reselect path and
  the findings loader landed; the event-only spy fixture needed
  the level column as string to match the real store. Fixed:
  per-purpose context window plus safety margin in config with the
  input+output+margin invariant enforced at load (shipped triage
  24000/4200/2000 within 32768, analysis 56000/6000/2000 within
  65536), estimator recalibrated to 3 chars/token against the live
  3.2 measurement, one 25% evidence shrink on a context 400 then
  give-up as ai_failed with `context_overflow`, findings loaded
  from the findings table with the same row-group pushdown, and
  bounded projections (no raw_data, 300-char command cuts) with
  separate findings/events counts while the scan still sees full
  records. Measured on the real incidents 146 (273 findings + 273
  events: all findings + 2 events, prompt estimate 23,493) and 192
  (297 + 294: 274 findings + 0 events, estimate 23,469), both under
  the 24000 cap; exact token counts not measured (model server
  unreachable); loader contrast re-measured on the same 46-uid
  call: old 1.66 s / 2.36 GiB vs new 0.28 s / 370 MiB. Verified
  with `make lint` (green), the full `make test` (653 passed with
  Postgres, including 45 triage tests) and `pre-commit run
  gitleaks --all-files` (Passed). No eval delta. Compose Postgres
  left running. Awaiting maintainer commit.
- 2026-10-29: fix round 3 on triage (live run: 2.48-2.54 chars/token
  broke the 3.0 estimator, timeouts left no rows, 86 identical
  findings ate the budget). Failures first: the two new call tests
  failed as reported (stored error message is the fixed literal
  "transport raised", not ""; the billed hold_ttl probe missed the
  cloud egress filter) and both were fixed in the tests, not by
  weakening code. Fixed: estimator 2.4 chars/token with the three
  measured (chars, exact tokens) pairs in the calibration fixture;
  raised transport failures recorded as rows (timeout vs
  connection_error by type only, zero tokens, fixed-literal message,
  holds released; exception codes feed the trail but never trip the
  early stop alone, so timeout x3 keeps 3 rows); per-purpose read
  timeout (triage 300 s, analysis 180 s) driving transport, hold_ttl
  and lease sizing via _resolve_lease (CLI --lease-seconds defaults
  to it); shipped triage input cap 12000 (invariant holds;
  untested at that size, no latency claimed); one group line per
  (rule_id, host) with validator accepting every incident uid.
  Measured on the real incidents 146 (546 uids: 273 findings in 1
  group all shown, 146/273 events in, user estimate 11295 < 12000)
  and 192 (591 uids: 297 findings in 13 groups all shown, 116/294
  events in, estimate 11319); loader wall 0.2-0.4 s, whole-process
  peak RSS ~200 MB (corroborated by /usr/bin/time -l: 210075648
  bytes); exact token counts not measured (model server unreachable
  from the sandbox). Verified with `make lint` (green), the full
  `make test` (664 passed with Postgres) and `pre-commit run
  gitleaks --all-files` (Passed). No eval delta. Compose Postgres
  left running. Awaiting maintainer commit.
- 2026-10-29: fix round 4 on triage timeouts (live run: 2 tries at
  about 250 s each for one incident, 3 timeouts at the 300 s read
  timeout for the other; output tokens dominate). Fixed: triage
  output cap 3000 with the context-window invariant holding, triage
  default read timeout 900 s derived as output cap over assumed
  tokens/s plus 150 s prefill margin with an explicit timeout winning
  and non-positive rates refused, lease and hold TTL following the
  read timeout; timeout and connection-error codes take part in the
  same-code early stop with one 25% evidence shrink after a first
  timeout; every model-visible time renders as ISO-8601 UTC with
  seconds precision while stored data keeps the raw epoch. Measured
  on the real incidents 146 and 192: not measured (model server
  unreachable from the sandbox; exact tokenize counts and estimates
  unavailable). Verified with `make lint` (green), the full `make
  test` (671 passed with Postgres) and `pre-commit run gitleaks
  --all-files` (Passed). Security-reviewer pass: no new network, no
  secrets logged, transport failures keep the fixed literal, fences
  and truncation unchanged, hostile-evidence tests green. No eval
  delta. Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-29: triage bare-IP fix (prompt 18 follow-up; live Glimmer
  triage returned `ip` entities carrying a port, which passed grounding
  because the string appears literally in the evidence). Fixed: one
  sentence in the triage system message (`ip` entities carry only the
  address, never a port; IPv6 without brackets), plus a `malformed_entity`
  semantics check (`ipaddress.ip_address`, no silent port stripping) that
  flows into the correction retry exactly like `invented_entity`; grounding
  still runs on the same value so both codes can co-occur. New tests in
  `tests/test_triage.py` cover port/bracket/hostname/CIDR rejection, bare
  IPv4/IPv6/IPv4-mapped acceptance, non-`ip` types untouched, retry-resolves
  and always-fails end-to-end cases, and correction-message contents.
  Verified with `make lint` (green: ruff, format, mypy) and the 27 DB-free
  triage tests (green); full `make test` not green in this sandbox (no
  Postgres: container runtime broken, DB guard fails; sandbox also blocks
  the networked egress/transport tests), so the 2 DB-backed end-to-end
  tests are written but not run here. Measured port-bearing `ip` count:
  not run (corvus database unreachable from the sandbox; no model called).
  Security-reviewer pass: prompt text is static, correction echoes only the
  offending value back on the on-prem path, stdlib parse only, no new
  deps; accepted residual: a scoped IPv6 form passes the parse but stays
  evidence-grounded. No eval delta (live Glimmer check left to reviewer).
  Awaiting maintainer commit.
- 2026-10-29 (correction): the bare-IP change above shipped a duplicate
  top-level helper in `tests/test_triage.py` (a second `_attempt_rows`
  with a different column shape silently replaced the original, breaking
  6 pre-existing DB-backed tests; invisible without Postgres). Fixed by
  renaming the new helper to `_validator_rows`, used only by the two new
  end-to-end tests; an AST duplicate-name scan of `tests/` is clean and
  the 27 DB-free triage tests still pass. Added one AGENTS.md test rule
  (grep a test module before adding a helper; ruff F811 is enabled via
  `F` but verified not to flag duplicate function definitions, so no
  config change). DB-backed tests still not run here (Postgres
  unreachable from the sandbox); reviewer reruns the full suite.
  Awaiting maintainer commit.
- 2026-10-29: triage output cap 3000 -> 4500 tokens and omitted-`language`
  fix. `corvus/llm/config.py`: triage `max_output_tokens` 4500, derived
  default read timeout 4500/4.0+150 = 1275 s (lease and hold TTLs follow
  the derivation); docstring and timeout comments updated. Invariant
  12000 + 4500 + 2000 <= 32768 still holds and keeps its test.
  `corvus/llm/call.py`: validator 3 now applies the response schema's
  `language` default when the field is omitted (new generic
  `_schema_language_default`, works for triage and the future analysis
  schema), so an omitted field counts as the schema default; a missing
  field against a different requested language still fails with
  `language_mismatch` and a message telling the model to set `language`
  explicitly; explicit wrong values still fail, other validators
  untouched. Triage system message gains one sentence: always include
  the `language` field in the JSON. New tests: omitted+English passes,
  omitted+Spanish fails with an instructive message, explicit
  wrong/right checked, and end-to-end first-answer-without-`language`
  resolves on try 1 with one `ok` attempt row (in both
  `tests/test_llm_call.py` with a default-carrying verdict shape and
  `tests/test_triage.py` with the real `CondensedIncident`); helper
  names grepped for duplicates before adding; pinned 3000/900 test
  values updated to 4500/1275.0 (the 1500-cap/2.0-rate derivation case
  stays 900.0). Verified with `make lint` (green: ruff, format, mypy)
  and 66 DB-free tests across the three touched files (green); the
  Postgres-backed tests (including the 2 new end-to-end tests) error on
  the `DATABASE_URL` guard here (no database reachable from the
  sandbox, container runtime blocked), reviewer reruns the full
  `make test`. Gitleaks v8.30.1 (the pre-commit-pinned rev, run from a
  /tmp binary as pre-commit is not installed here): no leaks found over
  41 commits plus the worktree. Full `UV_CACHE_DIR=/tmp/uv-cache make
  test`: 19 failed, 517 passed, 149 errors -- zero failures in the
  touched files; every failure/error is environmental (DATABASE_URL
  guard with no Postgres reachable, or sandbox PermissionError on raw
  sockets in egress/transport/TLS tests), none in the changed code
  paths. Awaiting maintainer commit.
- 2026-10-29: built the Spark read-only tools (`corvus/llm/tools.py`,
  `tests/test_spark_tools.py`, 21 tests): `get_events` (pseudonym-only
  filters resolved server-side, ISO-8601 windows, inventory-gated
  classes with visibility-gap observations, count+size caps with a
  showing-N-of-M note, triage-fenced projections through cloud
  `prepare_payload` with the whole incident's entities registered
  first) and `get_attack_technique` (exact-key lookup; unknown/revoked
  are errors), plus `collect_incident_entities` reusing the triage
  loader rows and projections, and per-call `execute_tool_calls` that
  never drops siblings. `make lint` green (ruff, format, mypy over 60
  files); new suite 21 passed with Postgres; full `make test`: 704
  passed, 1 failed in `tests/test_triage.py` on the calibration
  fixture deleted from the worktree before this prompt (tracked in
  HEAD, unrelated to this change). Gitleaks hook passed. Compose
  Postgres left running. Awaiting maintainer commit.
- 2026-10-29: scoped Spark `get_events` to a per-run pseudonym
  allowlist (`corvus/llm/tools.py`, `tests/test_spark_tools.py`, 27
  tests): out-of-scope pseudonyms get the byte-identical unknown-
  pseudonym error, the allowlist grows from shown HOST-/USER-/IP-
  pseudonyms after each turn (strict same-turn rule, persist/restore
  documented for the loop), gap wording now names the source window
  and count lines say limit-reached or N-of-N. `make lint` green;
  new suite 27 passed; full `make test` 712 passed; gitleaks passed.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-29: closed the allowlist echo bypass (`corvus/llm/tools.py`,
  `tests/test_spark_tools.py`, 32 tests): allowlist grows only from
  typed fields of server-returned result structures, `ToolError` fixed
  messages replace all model-text echoes, other errors map generic.
  `make lint` green; new suite 32 passed; full `make test` 717
  passed; gitleaks passed. Compose Postgres left running. Awaiting
  maintainer commit.
- 2026-10-30: built the bounded Spark agent loop (`corvus/llm/agent.py`,
  `corvus/llm/call.py` ToolLoop, `AnalysisVerdict` in
  `corvus/llm/schemas.py`, migration `0006_agent_step_scope.sql` for
  `agent_steps.shown_pseudonyms`, `corvus analyze` CLI,
  `tests/test_analysis_agent.py` with 22 tests): max 6 tool calls then
  a tool-free final turn, token budget and wall-clock deadline from
  configuration, refusal/truncated recorded tries, steps persisted as
  they happen with resume from persisted steps plus a written summary
  (allowlist rebuilt as incident entities UNION shown sets),
  queue claim/heartbeat/lease so two workers never both spend, verdict
  pseudonyms mapped back on-prem at store time. Security pass: shared
  the signal list so tool-result injection reaches validator 5 (new
  quarantine test); residual bare-word pseudonymizer limits documented
  in code. `make lint` green; full `make test` 739 passed with
  Postgres; gitleaks passed. Test env note: the in-network database
  password in the env file is stale against the reused volume; test
  runs build the host-mapped URL with that file's compose password
  (read-only, file untouched). Compose Postgres left running. Awaiting
  maintainer commit.
- 2026-10-30: fix round from the first real Spark runs (prompt 19b, no
  paid calls made here; the two named fixtures were missing from the
  worktree and were reconstructed from the report, marked as such):
  strict schema copies for cloud backends (`corvus/llm/call.py`,
  full `required` plus `additionalProperties: false` at every object
  level, Glimmer byte-identical), sentence-punctuation pseudonym
  replacement (`corvus/guardrails/pseudonymizer.py`, trailing `.?!`
  runs kept after the pseudonym; dotted names still one unit, longer
  tokens still untouched), incident-scoped triage (`WorkQueue.claim_job`,
  `enqueue_triage_jobs(incident_ids=)`, `process_incident_triage`, CLI
  uses it), egress allowlist from resolved settings (META default
  counts when unset, fail closed), AGENTS.md rule 10 (verify against
  the real API). New tests: 2 call, 7 pseudonymizer, 1 payload sweep,
  2 CLI scoping, 1 queue, 2 triage, 2 egress (1 updated, 1 new).
  `make lint` green; full `make test` 755 passed with Postgres;
  gitleaks passed. Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-10-30: lease fix round (paid verdict lost past 60 s): one
  resolved lease per run (explicit, else backend read timeout) for
  the claim and the heartbeat (`corvus/llm/agent.py`), heartbeat
  interval from `min(lease, granted remaining) / 3`
  (`corvus/state/queue.py` `heartbeat_interval_for`, also used by the
  triage worker whose own paths were already consistent). Failing
  first: scaled 0.6/1.8 reproduction ended busy pre-fix. New tests: 3
  lease cases plus 1 interval unit. `make lint` green; full `make
  test` 759 passed with Postgres; gitleaks passed. Compose Postgres
  left running. Awaiting maintainer commit.
- 2026-10-30: added the paid model-path eval (`eval/llm_harness.py`,
  `corvus eval llm --min-floor 4 --analyze N --lang en|es --labels
  visible|blind --max-usd X --concurrency C`, reports
  `eval/reports/llm_latest.md`/`.json`): scoped triage enqueue with a
  new `min_floor` filter (`corvus/llm/triage_worker.py`), floor-first
  selection (largest day-1-covering incident, then id), resumable
  (resolved skipped, second run zero model calls), max-usd stop,
  per-incident progress. Metrics with n: per-model/purpose
  first-pass validity, avg attempts, outcomes, token-source share,
  tokens/USD per resolved, wall median/p90 plus labelled remaining
  estimate, day-1 timeline coverage (best/all), hallucinated-uid
  share, ATT&CK accuracy blind-only, benign from adversarial
  fixtures, floor-hold. Five `eval/adversarial/` fixtures (RFC 5737
  + example.com, each with a clean twin, one tool-result variant).
  Anti-leakage: request-body markers check (test-mode capture) and
  the pseudonym-table deny-list check over persisted texts, both
  fail the run. New `tests/test_eval_llm.py` (17 tests: math on
  hand-written rows, max-usd stop, resume, scoped queue rows,
  leakage hits on planted strings, blind attack removal, honest and
  obeying adversarial, tool-result quarantine) plus sentence-final /
  FQDN-final / ellipsis / upper-case / mid-path pseudonymizer tests.
  Failing first: cost formula uses cached-input discount, JSONB
  needs `jsonb_array_elements_text`, stub summaries need stopwords,
  obeying suppress verdicts quarantine (validator 5 steering check
  ignores `timeline` evidence; `requested_verdict` never set —
  measured and pinned, no product change). `make lint` green; full
  `make test` 777 passed with Postgres. Live model run not done
  here (reviewer runs it); cost bound assume full caps zero cache
  hits: 0.10 USD per analyzed incident. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-30: built the reduced read-only UI (frontend-engineer, then
  security-reviewer pass). Failures first: none in the final runs.
  Counts: `make lint` green; full `make test` 784 passed with
  Postgres; `make ui-test` 3 passed; `make ui-build` built;
  gitleaks passed. Added the `adv-llm:` exclusion in the eval
  selection and every API listing, the read-only incident/health
  API with strict CSP, and the React+Vite SPA under `ui/` served by
  the same FastAPI app. Compose Postgres left running. Awaiting
  maintainer commit.
- 2026-10-30: registry-quality fix (llm-engineer, then
  security-reviewer pass; no paid API call). File and executable
  names and non-host path components never register as host or
  domain; free-text FQDN registration needs a real public suffix;
  one host token covers the short host and its FQDN form, including
  the typed host field. Triage-model entities register only on a
  canonical match with typed event fields (drops counted in a log
  line, no values). `get_events` with no entity filter now lists
  only this run's allowlisted pseudonyms and its schema says at
  least one filter is required. Analysis claiming is scoped to the
  requested incident's job, so concurrent analyses cannot steal
  jobs. Added the dry-run-by-default `corvus db clean-pseudonyms`
  one-off (referenced rows kept, counts only). New tests: 14 in a
  new registry suite (including a bounded replay-store check that
  registers no file-named host/domain rows), plus 1 tool test and
  1 concurrent-analysis test; 2 pre-existing assertions updated to
  the new file-name behaviour. Verified with `make lint` (green)
  and the full `make test` (800 passed with Postgres) and
  `pre-commit run gitleaks --all-files` (Passed). No normalizer or
  correlation change, so no eval delta. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-30: fixed the UI findings (frontend-engineer, then
  security-reviewer pass). Hash routing with no router library
  (`#/` list with page and filters, `#/incidents/<id>` detail,
  Back/Forward via hashchange; non-numeric or unknown ids render a
  static error, never a blank page or an echoed id). API filters
  (`verdict`, `analyzed`, existing `min_floor`) with static-body
  422s for unknown values; default sort analyzed first, then floor
  descending, then id (stable, paginated). Verdict column shows
  `triaged` / `pending` distinctly with badges for the four stored
  verdicts; rows fully clickable and keyboard reachable with
  link-styled titles. Incident view shows per-step tool, key/value
  arguments, one-line summary plus full result in a collapsed
  monospace block capped at 4000 chars, readable severity-factor
  list with raw JSON collapsed, per-attempt cost table plus total,
  and the unverified-reasoning heading only when stored text
  exists. Narrow layout hides the Final/Events/Injection columns;
  focus-visible covers rows and selects. Counts: `make lint`
  green; full `make test` 803 passed with Postgres (10 in the API
  UI suite, 3 new); `make ui-test` 18 passed (15 new);
  `make ui-build` built; gitleaks passed. Security-reviewer pass:
  text-only rendering, no new network destinations, all filters
  parameterized, adversarial hash and injection tests green. No
  normalizer, correlation, prompt or model change, so no eval
  delta. Layout widths reasoned from CSS, not measured in a
  browser. Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-10-30: mapped the Linux archive baseline to typed OCSF 1.9.0
  (detection-engineer; no paid API call). Census
  (`eval/linux_census.py`, `eval/reports/linux_baseline_census.md`):
  n=157451 over 2026-10-28T00:00:01Z..2026-10-31T00:00:00Z, 2 agents,
  benign lab activity only (cron, systemd, monitoring, a few ssh
  sessions; no attack, no Failed/Invalid-user lines). Current
  normalizer mapped 107103 (1007: 107009, 3002: 89, 1001: 5).
  Normalizers (`corvus/normalize/wazuh.py`): sshd
  Accepted/Failed/Invalid-user/disconnect/closed to 3002 (auth
  method and invalid-user flag in unmapped; user verbatim up to a
  256-char cap), pam/su sessions to 3002 Logon/Logoff (cron tagged
  for later filtering), execve SYSCALLs to 1007 with the EXECVE and
  PROCTITLE records joined by serial (hex decoded, replacements
  counted; quoted values stay literal), USER_AUTH/USER_START/LOGIN/
  USER_END to 3002, USER_CMD to 1007, watch-key file syscalls to
  1001 via joined PATH records (last non-trivial path wins), connect
  syscalls to 4001 via the decoded SADDR peer (present in every
  baseline connect blob), event time from the log line, dedupe keys
  (syslog: agent plus canonical body; audit: agent plus serial).
  Loader (`corvus/adapters/replay/linux_loader.py`, `corvus replay
  load-linux`): archives into data/replay-linux with file SHA-256
  plus line provenance, serial-join window, manifest-skipped reruns;
  measured n=157451 to 55794 events (1001: 17080, 1007: 31373,
  3002: 3819, 4001: 3522), 81119 unmapped, 2935 merged, 17603
  deduplicated, 0 malformed. Injection detector needed no field
  change (ssh user, cmdline, file path already scanned; end-to-end
  test added). Sigma report
  (`eval/reports/linux_sigma_coverage.md`): 149 linux rules in the
  full bundle, 0 routable by the windows-only engine, 0 false
  positives (vacuous); per-service field gaps listed. 16 real-record
  fixtures plus 38 tests; full-conformance sweep 0 errors on all
  mapped events. One existing adapter test pinned manager-time
  event times, so log-line time applies to the raw-doc path only
  (hit path keeps cursor-sorted manager time). Verified with `make
  lint` (green) and the full `make test` (841 passed with
  Postgres) and `pre-commit run gitleaks --all-files` (Passed;
  direct tree detect flags only pre-existing git-ignored data,
  llm_latest.json and pycache, none in changed files). Windows eval
  harness untouched, no shared-path behavior change, so no eval
  delta. Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-30: added Linux detection routes and the learned-rule
  verifier (detection-engineer). `corvus/detect/mapping.py` routes
  `linux/process_creation`, `linux/file_event`,
  `linux/network_connection` (verified field-by-field against the
  real normalized chain events); auditd-service and
  syslog/sshd/cron shapes stay unrouted and counted. Shipped Linux
  rules measured by `eval/linux_rules_measured.py` into
  `eval/reports/linux_rules_measured.md`: 149 inventoried, 73
  evaluate, 7 baseline matches on 7 events (n=55794), 5 chain
  matches on 5 events (n=3567), chain steps 1-6 uncovered by any
  shipped rule. New `corvus/learning/backtest.py` (21 stable codes,
  same engine and mapping as shipped rules) and
  `corvus/learning/rules.py` over the rules table plus migration
  `0007_rules_native_uid.sql` (unique native id, no reuse), with
  `corvus rules backtest/add/list/show`. Golden control
  `tests/fixtures/rules/linux_golden_rule.yml` accepted (2 target
  hits, 0 baseline); the broad sibling rejected with
  `over_broad_literal`. Verified with `make lint` (green), the full
  `make test` (879 passed with Postgres), `pre-commit run gitleaks
  --all-files` (Passed), and the Windows detect harness before and
  after (delta +0 on every count). Compose Postgres left running.
  Awaiting maintainer commit.
