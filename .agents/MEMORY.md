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
