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
