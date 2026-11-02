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
- 2026-10-31: built the Spark rule-proposal loop (detection-engineer).
  Pipeline check on a temp store copy (read-only data): shipped Linux
  rules give 5 matches on 5 events over the chain store, correlating
  to 1 incident (floor 4), so no pipeline fix was needed; the loop
  works from that incident. New `corvus/learning/rule_tools.py`
  (search_sigma_rules max 8 hits, backtest_rule returning only codes,
  counts, matched uids, baseline count) plus the shared allowlisted
  get_events; analysis never gains the new tools. New
  `corvus/learning/propose.py` (max 3 generate-backtest-correct
  rounds, tool/turn/token caps, optional per-proposal USD cap, strict
  RuleProposal schema, every turn in llm_attempts purpose
  rule_proposal with round codes, billed turns in spend; outcomes
  accepted/exhausted/rejected_unsafe/budget_stopped). Backtest gained
  the forbidden-token screen (`pseudonym_in_rule`,
  `attacker_literal`, token values never echoed). Lineage now carries
  source incident plus rounds/model/prompt version/ledger ids. New
  `corvus/learning/shadow.py` (same loader/engine/mapping, findings
  marked shadow and never persisted, hits/disposition counters,
  LEARNED_RULES_ENABLED kill switch) and `corvus/learning/proof.py`
  (`corvus rules prove`: stored rule fires 6 times on the control
  store with zero attempts/spend rows added, silent after rollback).
  CLI gained rules propose/approve/rollback/shadow-eval/prove; live
  turns go through a new `run_chat_turn` in `corvus/llm/call.py` so
  the single-entry transport gate stays green. `tests/
  test_rule_proposal.py` has 25 tests (pipeline, tools, loop,
  injection/exclusion/attacker-literal/bomb/oversize/unknown-tool
  safety, kill switch, proof, leak check, CLI). Docs section 4
  rewritten. Verified with `make lint` (green), the full `make test`
  (904 passed with Postgres), `pre-commit run gitleaks --all-files`
  (Passed), and the Linux rules measurement re-run (delta +0,
  report byte-identical). No paid API called. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-31: fixed the rule-proposal loop's missing assistant echo
  (live Spark returned HTTP 400 on turn 2: tool messages with no
  preceding assistant tool_calls). `assistant_tool_message` moved
  from `corvus/llm/call.py` to `corvus/llm/transport.py` and is now
  shared by both loops; `ModelResponse` carries `ToolCall` values
  with raw arguments, `ModelFn` takes the real message structure,
  and turn failures surface `ModelTransportError` (HTTP status,
  provider type, capped secret-free message) instead of a bare class
  name. New `tests/history_check.py` strict validator (same
  sequencing the provider enforces) drives a 2-tool-turn loop test
  against a 400-raising stand-in and now also checks the analysis
  3-turn histories. Verified with `make lint` (green), the full
  `make test` (907 passed with Postgres), `pre-commit run gitleaks
  --all-files` (Passed). No paid API called. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-31: fixed the two live Spark defects in the rule-proposal
  loop (detection-engineer). Budgets are now per tool (searches 4,
  event queries 6, reserved backtests 6 over 14 turns), enforced per
  call inside batched turns with budget-exhausted observations; every
  tool result carries the remaining counts and the system message
  states the budgets. A steer message fires with 3 turns left and a
  final without acceptance gets one reserved correction turn (+2
  turns, backtest-first). Final YAML is compared to the accepted
  round by parsed structure (formatting ignored); the verified text
  is stored, semantic diffs reject with the differing top-level
  keys. `tests/test_rule_proposal.py` has 8 new strict-history tests
  (search-forever, batched cap, reserved correction incl. at-cap,
  steer, reformatted/block-scalar equivalence and diff-keys). Old
  exhaustion tests moved from 3 to 6 rounds. Verified with `make
  lint` (green), the full `make test` (915 passed with Postgres),
  `pre-commit run gitleaks --all-files` (Passed). No paid API
  called. Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-31: shipped the learned-Sigma to Wazuh XML shadow path
  (detection-engineer). Fixed two live-review defects in
  `corvus/learning/rules.py`: Corvus assigns the Sigma id (fresh
  uuid4 via `prepare_candidate_text`, rewritten into the stored
  text; the model's id is ignored so it can never bump another
  rule's version) and the stored text is forced to `experimental`
  while deployment lifecycle stays in the row status column; the
  propose loop reports the stored id. New `corvus/learning/
  wazuh_xml.py` (pure Sigma linux/process_creation to Wazuh XML:
  sudo rule under parent 5400 on the decoded `command` field,
  auditd rule under parent 80700 as one PCRE2 `(?i)` regex over
  `full_log` with a plain-or-uppercase-hex alternation per literal
  plus an EXECVE/USER_CMD guard; shadow level 2 below the lab alert
  threshold 3, active 7; group `corvus_<sigma id>`; mitre ids only
  from the pinned dictionary; typed `translation_unsupported`
  refusals, never partial output; second native id is the next free
  id above the stored one). New `corvus/learning/export_wazuh.py`
  (`rules export-wazuh`: XML, raw `full_log` logtest inputs with
  location/agent, `expected.json` from fresh Sigma matches over
  both stores, plain-text deploy plan; refusals write nothing) and
  `corvus/learning/logtest.py` (`LogtestRunner` Protocol,
  env-command subprocess runner, archive/alert-shaped output
  parser failing closed, per-line Sigma-vs-Wazuh parity report;
  `rules logtest`; tests use stand-ins). Real-data parity: the
  control rule's 3 Sigma chain hits (2 sudo plain, 1 hex-only
  EXECVE arg) all fire on their Wazuh patterns. `tests/
  test_wazuh_xml.py` (29 tests) and `tests/test_export_wazuh.py`
  (22 tests) cover the subset, refusals (markup/NUL/newline/1MB
  literals, `|re`, bad logsource/field/level of negation, id
  collision/range, edited-in-DB text, runner garbage/timeout) and
  the CLI pair end to end. Architecture notes gained the
  shadow-mode flow and translator limits. Security pass: no model
  input reaches the XML (literals are escaped/screened, `|re`
  refused, patterns re-compiled plus empty-match guarded, XML
  rebuilt with ElementTree and re-parsed); runner command from env
  only; bundle carries no manager address. Verified with `make
  lint` (ruff check, format check, mypy green), the full `make
  test` (968 passed with Postgres), and gitleaks (Passed). No
  normalizer, correlation, prompt or model changes, so no eval
  delta. No paid API called, nothing executed against a server.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-31: fixed the shadow rule reaching its records
  (detection-engineer follow-up to a lab-manager 4.14.9 finding:
  parity was 324/326 because first-matching-sibling wins left the
  sudo rule under bare 5400 dead). `corvus/learning/wazuh_xml.py`
  now parses the shipped ruleset files (fragments wrapped for the
  stock parser; `*_rules.xml` only, decoders and local excluded)
  and derives each `if_sid` chain as the decoder-group root plus
  every direct child that could match first (children gated on
  `audit.type` outside SYSCALL/USER_CMD are dropped, which also
  removes the high-level anomaly rules; grandchildren are covered
  transitively): sudo under 5400/5401/5402/5407/5403/5405/5406,
  auditd under 80700/80780/80783/80786/80789/80792. Shadow level is
  per source at the highest replaced-parent level (sudo 5, auditd
  3; floored below log_alert_level for level-0-only chains), so a
  shadow child never hides or downgrades an existing alert; active
  stays 7. `parent_ids` override validated against the passed
  files (`unknown_parent` refusal). Deploy plan and parity report
  carry the exact logtest bridge contract (one JSON line in/out
  with decoder and rule blocks, command only via
  CORVUS_WAZUH_LOGTEST_CMD) plus the unchanged-count-and-level
  shadow check and the active-replaces-parent note. Tests:
  stand-in ruleset sibling shadowing, override refusals, level
  matrix 0/3/mixed/5, real sudo lines with real parent levels, and
  plan/report text. Verified with `make lint` (green), the full
  `make test` (979 passed with Postgres), and gitleaks (Passed).
  No paid API called, nothing executed against a server. Compose
  Postgres left running. Awaiting maintainer commit.
- 2026-10-31: shipped the live path (detection-engineer, with a
  security-reviewer pass). `corvus wazuh poll [--once | --interval
  SECONDS]` reads alerts through `WazuhAdapter.stream_alerts`
  (settings from `WAZUH_INDEXER_URL/USER/PASSWORD/CA` only, TLS stays
  on, credentials never in logs/errors/argv/DB), resumes from the
  checkpoints table, normalizes with the alert-hit mapper, writes a
  live replay-format store (provenance: index plus document id), and
  correlates/upserts incidents with no model call; `--with-archives`
  pulls host/window context per new incident and says plainly when
  the archives index returns nothing. Attribution
  (`corvus/live/attribution.py`): native-id join plus pair join via
  the shared `corvus_<sigma id>` group (the second native id is the
  next free id at export time, not anchor+1); incidents/findings
  carry rule id, Sigma id, version, shadow/active mode, lineage id;
  shadow and unknown findings never raise severity (recorded in
  `severity_factors.learned_rule_muting`), exposed read-only in the
  incidents API. `corvus rules ledger-check --start/--end
  [--expect-zero]` groups `llm_attempts`/`spend` by purpose/model;
  each cycle also writes a `wazuh_poll_cycles` row. New migration
  `0008_live_poll.sql` (`incidents.learned_rules`,
  `wazuh_poll_cycles`); additive `last_provenance` capture on the
  adapter. `tests/test_wazuh_live.py` (18 tests) uses verbatim lab
  shadow lines (2 sudo, 5 auditd of 313) for the pair fixtures plus
  stand-in transports for pages/overlap/out-of-order/malformed/5 MB/
  unicode+injection/non-numeric id/unknown 100999/401/500/timeout/TLS/
  crash-resume/double-run/ledger windows/no-llm-rows. Failures found
  first: 2 wrong test expectations (JSON-escaped raw check, late-doc
  timestamp), 1 empty-cycle archives flag fixed in product, 1 incident
  key-set test updated for the new contract. Verified with `make
  lint` (green: ruff check, format, mypy on 76 files), the full
  `make test` (997 passed with Postgres), eval harness to throwaway
  reports (every metric delta +0, both gates pass, 240 s wall), and
  gitleaks over every changed file (no leaks). No paid API called,
  nothing executed against a server. Compose Postgres left running.
  Awaiting maintainer commit.
- 2026-10-31: shipped gate 2, the live-run learning evidence command
  (detection-engineer). New `eval/gate2.py` plus `corvus eval gate2
  --rule ID --train-gt FILE --positive DIR --positive-gt FILE
  --negative DIR --negative-gt FILE [--baseline-dir DIR] [--out
  eval/reports/gate2.md]`: variant exports load through the existing
  Linux loader into temporary stores, Wazuh alert files are read as
  the SIEM's own verdicts, and the report starts with four anti-leak
  checks (rule created before the first variant step, cited events in
  the recorded accepted backtest and absent from both variant
  exports, no variant-declared value in the detection text, recorded
  model attempts all predating the variant). Any failure is INVALID
  (exit 1); malformed inputs refuse (exit 2). Positive needs the
  rule's own `corvus_<sigma id>` alerts on every `expected: detect`
  step and nowhere else (misses fail, expected-miss hits are
  surprises, out-of-window hits are false positives); negative must
  show zero (hits there contaminate, hits only there mean swapped
  inputs); the same rule must match zero baseline events via the
  same engine; the inclusive detection window must hold zero ledger
  rows while later rows stay reported. Limits, ledger, baseline and
  per-step tables are all generated from the data (ground-truth
  `expected` defaults to `detect`, unknown values refuse; no wall
  clock in any number). `tests/test_gate2.py` (25 tests) builds
  small synthetic stores from real auditd/alert shapes with fixed
  epochs: each anti-leak failure, negative firing, swap, surprise,
  miss, false positive, baseline hit, in-window spend (pinned
  inclusive at the last finding), empty export, unknown expected,
  and a 3-second clock-skew creation. Failures found first: 1 test
  expectation (distinct-rule double count, fixed in product) and 2
  CLI tests needing cwd-relative data roots. Verified with `make
  lint` (green: ruff check, format check, mypy), the full `make
  test` (1022 passed with Postgres), and gitleaks (Passed). No
  normalizer, correlation, prompt or model changes, so no eval
  delta. No paid API called, nothing executed against a server.
  Compose Postgres left running. Awaiting maintainer commit.
- 2026-10-31: fixed gate-2 check `b-lineage-in-training-windows`
  (detection-engineer): it compared cited uids against the recorded
  backtest but never against the `--train-gt` windows, so passing
  the variant ground truth as `--train-gt` still read VALID.
  Verified against the repo's own functions that neither the rule
  lineage (uids plus backtest counts) nor the incident row (uids
  plus first/last seen) carries per-event times, so cited-event
  timestamps now resolve from an explicit training replay store
  (`--train-dir`, default `data/replay-linux-chain1`) through the
  real evidence loader `load_replay_events_by_uid`. Out-of-window
  cited events are INVALID (`lineage_outside_training_windows`),
  unresolvable ones too (`lineage_event_unresolved`, never a silent
  pass); the backtest attestation and the absent-from-variant-exports
  checks stay. `tests/test_gate2.py` grew 4 failing-first tests on
  the same synthetic stores (variant file as train ground truth, one
  cited event outside among inside ones, unresolved uid via a
  pruned train store, edge-inclusive boundaries; the clean world
  stays VALID). Verified with `make lint` (green: ruff check,
  format check, mypy), the full `make test` (1026 passed with
  Postgres), and gitleaks (Passed). No normalizer, correlation,
  prompt or model changes, so no eval delta. No paid API called,
  nothing executed against a server.
  `eval/reports/llm_latest.*` untouched. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-31: closed six rule-store integrity gaps in
  `corvus/learning/backtest.py` and `corvus/learning/rules.py`
  (detection-engineer, security-reviewer pass). (1) Verdicts are
  hash-bound: `BacktestResult` carries the SHA-256 of the exact
  evaluated text, `add_candidate` recomputes it and requires
  equality, `accepted` True with `codes == ["accepted"]`, and every
  cited uid inside `target_matched`; the hash is stored in lineage.
  (2) Versioning via explicit `supersedes` rule id: first store is
  version 1 with a fresh id, a superseding store reuses the id at
  previous version + 1 and records it (dead per-id MAX query
  removed). (3) `transition_rule` reads `FOR UPDATE` in the writing
  transaction and accepts optional `from_status` (stale callers fail
  instead of chaining); two-thread barrier test asserts exactly one
  wins. (4) Semantic `attacker_literal`: for each forbidden token in
  the target events the rule is re-evaluated with every occurrence
  blanked to same-length X's; a lost match rejects (lexical check
  stays as fast path). (5) Exclusion narrowed: one NOT scope holds
  exactly one literal of 4+ chars, never `|re`. (6) Optional
  `CORVUS_RULE_APPROVERS` allow-list for transitions, unset means
  unchanged. Proposal loop sends the text hash with its verdict.
  Tests failing-first (fabricated dict, swapped text, split/regex/
  charclass bypasses against the chain-1 injection event, 30-value
  and or-wrap negations, concurrent movers, unlisted approver);
  existing suites updated to cite only matched uids. Verified with
  `make lint` (green: ruff check, format check, mypy), the full
  `make test` (1046 passed with Postgres), and gitleaks (Passed).
  No normalizer, correlation, prompt or model changes, so no eval
  delta. No paid API called, nothing executed against a server.
  `eval/reports/llm_latest.*` untouched. Compose Postgres left
  running. Awaiting maintainer commit.
- 2026-10-31: closed the three remaining rule-store defects from the
  independent review (detection-engineer, security-reviewer pass).
  (1) The store no longer trusts caller verdicts:
  `add_candidate` in `corvus/learning/rules.py` re-runs `backtest`
  itself on the exact text against the source incident's stored
  events plus the baseline (new keyword-only `chain_dir` /
  `baseline_dir`) and refuses unless the fresh result is accepted
  with `codes == ["accepted"]`; the caller verdict
  (`BacktestResult`/dict/None) is informational only and the fresh
  verdict is what lands in lineage; a missing or unknown incident
  is refused. `propose.py` passes text plus incident only (its
  hand-computed hash dict is gone), `rules add` takes required
  `--incident` with no caller-side backtest, and `proof.py` owns a
  fixed-key incident. (2) Versioning: new migration
  `0009_rules_sigma_version.sql` (unique index on the lineage Sigma
  id plus version); supersede locks the parent `FOR UPDATE` and, in
  the same transaction, requires it to be the latest non-archived
  revision and stores MAX(version)+1, so a double supersede
  (sequential or threaded) fails with `ValueError` and the index
  backs any residual racer; `load_stored_rules` in
  `corvus/live/poll.py` orders by version DESC and skips archived
  rows, so attribution keeps the latest active revision. (3)
  `transition_rule` strips the approver once and records the same
  string the allow-list compares. Architecture section 4 gained the
  two-line residual (one NOT of a single 4+ char literal stays
  allowed by design, visible in the rule text). Tests failing-first
  (forged self-hashed dict stored pre-fix, unordered attribution
  picking v1 pre-fix, raw `" ana "` recorded pre-fix, plus
  no-incident, cross-text, double/concurrent/stale/archived
  supersede pins); three obsolete caller-binding tests removed and
  their facets re-pinned as ignored-verdict tests; `gate2` valid
  world now reports one training incident. Verified with `make
  lint` (green: ruff check, format check, mypy), the full `make
  test` (1052 passed with Postgres), and gitleaks (Passed). No
  normalizer, correlation, prompt or model changes, so no eval
  delta. No paid API called, nothing executed against a server.
  `eval/reports/llm_latest.*` untouched. Compose Postgres left
  running. Awaiting maintainer commit.

- 2026-11-01: fixed six independent-probe redaction gaps, tests
  failing-first (llm-engineer, security-reviewer pass). (1) URL
  userinfo (`corvus/guardrails/egress.py`): scheme matches generically
  per RFC 3986 (covers `+`/trailing-`s` schemes) and userinfo ends at
  the last `@` (tried last-first, so a path `@` is not credentials);
  passwords may hold `#`/`?`/`/`/`!`/`@`, and a separable user is
  kept (`scheme://user:[REDACTED:credential]@host`, else the whole
  userinfo as before; marker text is never re-matched). (2)
  PowerShell `-Password`/`-Pass`/`-Pwd` (space, colon or `=`, quoted
  or bare) redact the value with the flag kept, first in the CLI
  alternation so the generic `-p` rule cannot eat the flag; the
  attached `-p` rule no longer matches `[`-led marker output (that
  cross-stage eat also lowercased sqlcmd `-P`). (3) ldapsearch
  `-w` glued and `--bindpw` (space/`=`) added, still case-sensitive
  (`-W` prompts, never matches); sqlcmd `-P` glued/`=` added with the
  uppercase flag preserved. (4) `net use` tokenizes quoted spans, so a
  quoted share with a space is kept and only the password is
  replaced. (5) Pseudonymizer (`corvus/guardrails/pseudonymizer.py`):
  even-length 12+ hex runs (either case, `0x` skipped for the IP
  matcher) decoding (UTF-8/UTF-16LE) to a registered entity are
  masked; decimal-integer IPv4 and JSON integers holding a registered
  quad's packed value map to its pseudonym (7+ digits only, booleans
  excluded); `docs/architecture.md` residual paragraph updated (hex
  now decoded; compressed/encrypted/other charsets stay). (6) New
  `_replace_free_text` unit pin fails when `_ip_match_body` returns
  None (canonical-only table, no scanner help); IPv6 None kept as the
  documented exact-matcher path, not dead code. Verified with `make
  lint` (green: ruff check, format check, mypy), the full `make
  test` (1109 passed with Postgres), and gitleaks (Passed). No
  normalizer, correlation, prompt or model changes, so no eval
  delta. No paid API called, nothing executed against a server.
  `eval/reports/llm_latest.*` untouched. Compose Postgres left
  running. Awaiting maintainer commit.

- 2026-11-01: fixed the sshd log-injection defect and hardened two
  parsers (detection-engineer, security-reviewer pass). (1)
  `corvus/normalize/wazuh.py` `_map_sshd`
  rewritten: every sshd pattern anchors at the message start (text
  after `sshd[<pid>]: `), only that first message kind decides the
  status, and the peer is parsed right to left (last `from <ip> port
  <port>`, or last bare `<ip> port <port>` for
  Disconnected/Connection-closed, with the port form tried first so a
  trailing port number never matches as an ip); the username is
  everything between the fixed prefix and that peer (spaces kept,
  flagged `linux.username_whitespace`; empty parses fall back to the
  decoded fields). The old unanchored `.search()` recorded the lab
  login-name probe as a Success for the injected user/ip; it now maps
  to Failure (Invalid-user line) / Logoff (Connection-closed line)
  with the true peer. (2) Alert path: the log line wins over the
  Wazuh-decoded `data` fields and differing decoded values are kept in
  `unmapped["linux.decoder_conflict"]` (user, ip, port as decoded).
  (3) `corvus/guardrails/injection.py`: new deterministic signals
  `sshd_username_whitespace` plus `sshd_username_embedded_message`
  (username carries `Accepted `, `Failed password` or ` from <ip>
  port `), fired from the parser flag on `user.name` with effect
  `other`, flowing through `detect`/`scan_events` into the incident
  signal list. (4) `_AUDIT_CWD` and the EXECVE header `[^)]*`
  bounded to `{0,64}` (measured 1.8 s old vs 0.007 s new on ~400 KB
  of repeated heads; timing tests ceiling 1.0 s). (5)
  `docs/architecture.md` states the source-authority rule (log line
  wins for sshd/auditd command/path/`USER_CMD` user; decoded `data`
  wins for kernel-attributed auid/uid and for sudo, whose mapper
  reads only decoded fields); `tests/test_log_source_authority.py`
  (9 tests) pins each disagree case with no behavior change. Tests
  failing-first: `tests/test_sshd_injection.py` (34 tests: two real
  lab archive lines and one real alert copied verbatim into
  `tests/fixtures/linux/sshd_injection_*.json` and
  `tests/fixtures/wazuh/sshd_injection_alert.json`, every message
  kind with ordinary/spaced/spoof/non-ASCII usernames, both signals,
  both timing tests). Corpus regression via `eval/linux_census.py`:
  lab-archives identical before/after (mapped 56829, same classes);
  lab-chain1 3706 to 3708, both new rows the auth.log/journald
  copies of one `Connection closed by invalid user <token>` line the
  old translator dropped for the unknown marker (now correctly
  typed). Verified with `make lint` (green: ruff check, format
  check, mypy), the full `make test` (1152 passed with Postgres),
  and focused 43 passed; gitleaks unavailable in this sandbox (no
  binary; pre-commit hook fails building its Go env), manual review
  found no secrets in the diff. Normalizer change, so eval delta
  reported above; no prompt or model changes. No paid API called,
  nothing executed against a server. `eval/reports/llm_latest.*`
  untouched. Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-11-01: fixed the `Disconnected from ... [preauth]` sshd
  regression (detection-engineer). The peer is now parsed right to
  left for every sshd message kind with one shared shape (last `<ip>
  port <port>` with or without `from` before an optional `ssh2`
  plus key info or `[preauth]` suffix; IPv4/IPv6), the address must
  validate with the `ipaddress` module or the source stays unset
  with `unmapped["linux.sshd_peer_unparsed"]` (decoded fields are
  not consulted for it), and usernames keep their trailing-space
  strip on every branch. New `tests/fixtures/linux/
  sshd_real_corpus.jsonl` (9 verbatim lab lines, one per message
  kind, from the chain archive and the archives bundle) plus 16
  tests in `tests/test_sshd_injection.py` (corpus user/peer/status/
  activity, both task injection lines resolving to the last peer,
  bare/`[preauth]`/IPv6 peers, non-address peers leaving src unset;
  failing-first: 5 failed before the fix). Old-vs-new corpus check
  (`git show HEAD:` parser vs working tree over all sshd lines in
  both lab stores, 3270 docs): 4 diffs, all on lab-injection lines
  (bare pseudo-address now the real peer; two previously unmapped
  `invalid user` closed lines now typed from the real peer), zero
  other changes and no new flags anywhere. Eval delta: main
  harness to throwaway reports (all +0 vs committed baseline, both
  gates pass, 240 s wall) and `eval/linux_census.py` identical
  before/after (mapped 56829 of n=157451). Verified with `make
  lint` (green: ruff check, format check, mypy), the full `make
  test` (1168 passed with Postgres), and the gitleaks hook
  (Passed). No prompt or model changes. No paid API called,
  nothing executed against a server. `eval/reports/llm_latest.*`
  untouched. Compose Postgres left running. Awaiting maintainer
  commit.
- 2026-10-31: shipped the read-only learned-rules surface (detection-engineer,
  frontend-engineer, security-reviewer pass). API: `GET /api/rules` (status and
  mode allowlist filters with the static 422 body, paging capped at 100, stable
  id order; items carry status, mode, version, title, level, technique tags,
  hits, false positives, created_at, source incident id) and `GET
  /api/rules/{id}` (Sigma text, Wazuh anchor native id plus pair-secondary note
  and group, lineage with source-incident existence, cited uids, accepted
  backtest summary, rounds/model/prompt version/ledger ids, transitions with
  approver and reason, findings with incident links; native_text, bundle paths
  and credentials never selected into responses). Non-dict lineage degrades to
  empty with a note (200, never 500); deleted sources report exists false.
  Health self-observation now names the model behind the latest latency. UI:
  `#/rules` and `#/rules/ID` with nav link, shadow banner (alerts unchanged,
  corvus_shadow tag, no model weights updated), status/mode badges, Sigma code
  block with copy button, lineage/backtest/transitions/fired-in sections, and
  a distinct learned-rule badge in incident detail linking to the rule. Fixed
  the leftovers: health strip shows the latency model; 390 px pages measure
  scrollWidth 390 = innerWidth 390 on every route (see below). Security:
  GET-only, static errors, CSP and headers unchanged, no HTML sinks in
  `ui/src` (dist matches are React internals). Failing-first: 9 API tests
  failed before the routes existed. Verified with `ruff format` + `make lint`
  (green: ruff check, format check, mypy), the full `make test` (1186 passed
  with Postgres), the UI build plus `npm test` (40 passed, incl. the badge
  contrast test: every badge >= 4.5:1 both themes; light --ok nudged one step
  from 4.45 to 4.76), a real-browser check in headless Chromium (system Chrome
  and Firefox abort in this sandbox; the Playwright headless shell runs with
  --single-process): hostile 100 KB title/sigma renders as inert text on list,
  detail and incident pages (0 img/script/onerror/js-link elements, alert never
  fires), copy button flips to Copied with the Sigma text in the clipboard,
  learned badge links `#/rules/9`, focus order is nav/theme/Back/Copy/links
  and Enter opens a rule. The 390 px check first measured 1042186 px on the
  hostile rule detail (unbroken 100 KB token in the heading), fixed by wrapping
  long tokens in headings, paragraphs, lists and definition lists; re-measured
  390 on all four routes. Follow-up UI-only wrap fix rebuilt and re-tested
  (40 passed). Gitleaks hook Passed. No normalizer, correlation, prompt or
  model changes, so no eval delta. No paid API called, nothing executed
  against a server. `eval/reports/llm_latest.*` untouched. Compose Postgres
  left running. Awaiting maintainer commit.
- 2026-11-01: fixed the tool-result emitted-pseudonym scope, the double pseudonymization cost, and unbounded raw_data (llm-engineer, detection-engineer, security-reviewer pass). (A) `corvus/llm/tools.py`: `get_events` now reports the pseudonymizer's own emitted set per tool result alongside the typed-field shown set; `execute_tool_calls` gained `emitted_out`, and the allowlist still grows only from shown sets. `corvus/llm/agent.py`: new migration `0011_agent_step_emitted.sql` persists per-step `emitted_pseudonyms` (the allowlist seed excludes all emissions), one helper builds the verdict scope, and resume rebuilds it. (B) The analysis no longer pseudonymizes twice: the call layer unions the exact sent payload's emission into the verdict scope (fail-closed payload error when preparation fails), and the pseudonymizer builds one compiled alternation per table snapshot instead of one pattern per table entry per string. Measured on a scratch copy of a deployment table (read-only, no model called): one small incident `prepare_payload` 13.04 s wall before vs 1.04 s after, with byte-identical output and emitted sets on real triaged payloads. (C) Every string leaf inside `raw_data` caps at the documented length with original lengths kept in `unmapped`; small documents serialize byte for byte as before. Tests failing-first (2 scope tests failed with `ai_failed` before the fix); new `tests/test_analysis_tool_emitted.py`, `tests/test_pseudonymizer_single_pass.py` (legacy-vs-new differential) and `tests/test_raw_data_cap.py`; one vacuous assertion replaced with a real one. Verified with `make lint` (green: ruff check, format check, mypy), the full `make test` (1257 passed with Postgres), and gitleaks (git-aware scan: no leaks found; the 99 whole-tree hits sit in git-ignored data, bytecode cache and one untracked throwaway report, none in changed files). Model-bound payload bytes unchanged throughout. No paid API called, nothing executed against a server. Compose Postgres left running. Awaiting maintainer commit.
- 2026-11-01: fixed the single-pass pseudonymizer privacy leak (llm-engineer, security-reviewer pass). Root cause: the one-alternation scanner committed to the first same-spelling table entry at each position, so a path-exempt host row shadowed the user row the scan found in the same call and the real name left the box on the first call. `corvus/guardrails/pseudonymizer.py`: `_FreeTextReplacer` now compiles each entry's pattern once per snapshot and applies entries longest-first exactly like the committed loop (no per-string recompilation); the loop itself moved to `tests/oracle_pseudonymizer.py` as a frozen test-only oracle (`legacy_replace_free_text`, AST-verified identical to the committed code). New differential suite in `tests/test_pseudonymizer_single_pass.py` (6 tests): the table-collision case in all 6 row-insertion orders (fails on the old code: the first call returned the name unchanged), colliding raw values of different kinds, scan-only entities, 20 real triaged payloads (read-only copy of the deployment table into a scratch database, clear skip when absent) plus the synthetic fixtures, and 2000 seeded boundary-char fuzz strings with zero differences everywhere. `tests/test_pseudonymizer_gaps.py` now imports the oracle. Measured on a scratch copy of the deployment table (read-only, no model called): one payload about 1 s before vs about 0.4 s after, byte-identical to the oracle. Verified with `make lint` (green: ruff check, format check, mypy), the full `make test` (1262 passed with Postgres), gitleaks unavailable in this environment (no binary; no secrets in the changes). No normalizer, correlation, prompt or model changes, so no eval delta. No paid API called, nothing executed against a server. Compose Postgres left running. Awaiting maintainer commit.
- 2026-11-01: capped every typed Windows string at the documented cap (detection-engineer, security-reviewer pass). A multi-megabyte Image, User, ParentImage or TargetFilename used to land verbatim in `process.name`, `process.file.path`, `actor.user.name` and (via canonicalization) `entity_keys.user`; now `corvus/normalize/windows.py` routes each typed extraction through `_cap_text` (new `_capped_field` helper combining `_take_text` with the cap), recording the original length in `unmapped` under per-field `windows.*_truncated` keys: images, users, domains, computer name, file/registry paths, service fields, hashes, IPs and the 99-Other service captions. No pipe mapper exists (Sysmon 17/18 are unmapped), so no pipe slot needed a cap. Failing-first probe on the committed code showed all six slots leaking at full length. New tests in `tests/test_raw_data_cap.py` use the real Sysmon shapes for Image, User, TargetFilename and ParentImage plus registry, service, logon and host cases. Rule-10 proof: the committed module side-loaded against the fixed one over fixtures plus real benign and EVTX records gives 143 compared with 0 mismatches and 0 truncation keys fired, so model-bound payload bytes are unchanged. Audit: the Wazuh alert/archive mappers still copy uncapped attacker-controlled strings into typed slots (`sudo` command/users, auditd command/exe/auid-uid-euid users, file paths, `USER_CMD` command, `pam` actor, `su` invoker, syscheck paths/digests, agent name/ip, rule descriptions into finding titles) and the Linux loader inherits them via `map_linux_doc`; only `sshd`/`pam`/`su`/`audit-session` subject users are capped (256) and `raw_data` leaves (65536). Verified with `make lint` (green: ruff check, format check, mypy), the full `make test` (1265 passed with Postgres), gitleaks unavailable in this environment (no binary; no secrets in the changes). No correlation, prompt or model changes, so no eval delta. No paid API called, nothing executed against a server. Compose Postgres left running. Awaiting maintainer commit.
- 2026-11-01: closed the typed-cap mutant gap (detection-engineer). Reverting any single `_capped_field` call to `_take_text` went undetected at 24 of 27 sites; new parametrized suite in `tests/test_raw_data_cap.py` (tests only, no product change) covers every typed Windows slot: a 48-case matrix (Sysmon 1/3/7/11/12/13/14, Security 4624/4625/4697/7045, plus 4104 for the shared script-actor sites) feeding a 5,000,000-character value per field and asserting the slot fits 65,536 characters with the length in `unmapped`, 5 unmapped-layout cases (Sysmon 15/22, Security 4688/4720/4732 stay `UnmappedEvent`), and 5 exact-boundary cases (65,536 intact, 65,537 cut). Failing-first by reverting each of the 27 sites one at a time (scratch script, production file restored byte-identical, sha256-checked): 27 of 27 mutants detected. Verified with `make lint` (green: ruff check, format check, mypy), the full `make test` (1323 passed with Postgres), gitleaks unavailable in this environment (no binary; no secrets in the changes). No product-code change, so model-bound bytes and eval metrics are untouched. No paid API called, nothing executed against a server. Compose Postgres left running. Awaiting maintainer commit.
- 2026-11-02: pinned the surviving mutation-run behaviors with tests only (detection-engineer, llm-engineer, platform-engineer, security-reviewer pass). New `tests/test_mutant_pins.py` (106 tests, no production change): correlate auth-outcome routes (status_id-only, text-only, neither), factor-4 unrelated-host/user exclusion, hostless/disjoint cross-host joins (incl. a remote-IP-only join and a disjoint-shared-user join that kill the or->and and arm-deletion mutants), muted breadth/entities without severity (all-muted pins severity input 1 and shadow_only), tactic-only TA mapping plus unknown-shortname ValueError, evidence-only and related-only uid sources, title pluralization, breadth-3 score, failures_before with same-ms failure and smallest-uid witness; severity floor (Low-stage breadth cap at Medium, low cap ignoring breadth 2, no-tactic floor 1, tactic_order tie-break); egress wildcard boundaries and port isolation, default-port derivation (https->bare, http->bare, :80 only when named), userinfo and percent-encoded host refusal (reason pinned), 2-char quote-strip, /user: and api_key redaction; spend cap degrading at exactly the cap and at 0, per-branch bool/NaN/inf/negative/string rejection on every ttl/timeout/margin/worst_case/cap parameter, and record_spend returning the computed cost; suppression steering (agreement, below-floor, benign each alone; evidence clears all three), non-string/empty sshd names with actor fallback, embedded-message detection, metadata-uid fallback order; dictionary tactic_names/len plus revoked/deprecated/sub-of-revoked resolve; empty emitted sets on error/unknown-tool/bad-argument/out-of-scope/adapter-failure tool paths; KeyboardInterrupt/SystemExit propagation from correlate _signals_for and engine slice load/build (the swallowing mutant is except-BaseException; deleting the re-raise is a no-op since except-Exception never catches them), normal-exception skip counting, surrogate boundaries U+D800/U+DBFF/U+DC00/U+DFFF replaced with U+D7FF/U+E000 kept (unit plus full evaluate() runs), and the purge advisory-lock blocking plus 8-thread register/purge issuance. Verification: every test run against its mutant in a scratch copy outside the repo (PYTHONDONTWRITEBYTECODE=1), 64 of 66 killed; the 2 survivors are documented characterization pins (surrogate-range widening is unobservable because replacement only runs after a UnicodeEncodeError; the 8-thread issuance property also holds without the purge lock since register serializes on its own lock, while the blocking test kills the lock removal). Two test-authored bugs found first by the harness (related_uids [] fell back to [ref_uid]; percent/userinfo cases refused by earlier checks, sharpened to https and the percent reason). Verified with `make lint` (green: ruff check, format check, mypy), the full `make test` (1466 passed with Postgres), gitleaks unavailable in this environment (no binary; no secrets in the changes). No normalizer, correlation, prompt or model changes, so no eval delta. No paid API called, nothing executed against a server. Compose Postgres left running. Awaiting maintainer commit.
- 2026-11-01: fixed the six independent-review findings in correlate, detect, pseudonymizer and the Wazuh/Linux normalizers (detection-engineer, llm-engineer, security-reviewer pass). (A) `corvus/correlate/correlate.py`: unknown tactic ids (e.g. TA9999) are ignored like unknown techniques and recorded under `severity_factors["attack_unknown_tactics"]` instead of aborting the batch; each finding's `_signals_for` resolves in isolation (skips counted under `severity_factors["unresolved_findings"]`, `KeyboardInterrupt`/`SystemExit` still propagate), so a stored TA9999 finding no longer poisons the live poll and the cycle completes with the cursor saved. (B) Clusters are indexed by join key with window eviction (a cluster failing a time condition can never match again), keeping exact results at linear cost: old 10.6 s vs new 0.19 s at 8000 distinct-host findings, old ~164 s vs new 0.81 s at 30000; `tests/test_correlate_differential.py` proves byte-identical incidents (keys, floors, factors, uids) against a brute-force oracle on the 6074 real replay findings plus 20 shuffles (clear skip when data is absent). (C) `correlate_findings` dedupes by `metadata.uid` keeping the first in canonical order (a duplicated finding no longer counts twice). (D) `corvus/detect/engine.py`: extracted rows replace lone surrogates with U+FFFD (NUL handling unchanged), counted under stats, and a slice-build/load failure marks only its group's rules errored instead of aborting `evaluate()`; tests use a real Sysmon shape with a surrogate in CommandLine between two good events (old code loses the whole group with UnicodeEncodeError). (E) New migration `0012_pseudonym_counters.sql`: monotonic per-kind counters (seeded from the table maximum, advanced under the existing advisory lock) so purging never reissues a number (old max-plus-one reissued the top purged number, reproduced first); the purge takes the same lock and its referenced check now covers `shown_pseudonyms`/`emitted_pseudonyms`; `transition_rule` maps a non-object lineage to `ValueError`. (F) `corvus/normalize/wazuh.py`: new `_cap_typed` helper applies the single documented 65536 cap (asserted equal to the Windows cap) at 26 sites covering every string the Wazuh alert/archive mappers and the Linux loader copy into a typed slot, finding title or entity key, with original lengths in `unmapped` under per-field `*_truncated` keys; the 256-char user cap is untouched. Tests in `tests/test_wazuh_typed_caps.py` feed 5,000,000-character hostile values per site plus boundary and byte-identity checks; reverting each of the 26 sites one at a time fails a test (26/26 killed; merge sites verified separately). Differentials: 395 real fixture and lab documents map byte-identical before/after, so no eval delta; no prompt or model changes. Failing-first throughout (old raise test, dedup count, surrogate group loss, counter reuse, cap leaks, migration list). Verified with `make lint` (green: ruff check, format check on 191 files, mypy on 76 files), the full `make test` (1360 passed with Postgres), gitleaks unavailable in this environment (no binary; no secrets in the changes). Test env note: the outside-repo env file was absent, so it was recreated from the running container config plus a dedicated test database role (maintainer credentials untouched); compose Postgres left running. Awaiting maintainer commit.
