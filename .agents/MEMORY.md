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
