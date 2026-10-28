# Corvus architecture

Corvus is NOT a SIEM. It is an AI SOC analyst that plugs into the SIEM the
organization already runs.

- The SIEM detects atomic events and stores logs. Corvus does not replace it.
- Corvus consumes SIEM alerts, queries the SIEM for context on demand
  (it does not re-ingest all logs), correlates alerts into attack chains
  deterministically, reasons over them with AI, hunts in what was not
  correlated, learns new detections, and pushes them back to the SIEM as rules.
- Every attack Corvus catches makes the customer's SIEM better, even when
  Corvus is off.
- Hackathon scope: Wazuh only. Splunk and Elastic adapters are roadmap.

Data flow (hackathon):

```
Wazuh alerts/archives -> SiemAdapter -> OCSF -> deterministic correlation + ATT&CK
  -> Glimmer triage (on-prem, raw evidence) -> condensed incident
  -> pseudonymizer -> Spark agent loop (pseudonymized only)
  -> Sigma rule proposal -> backtest -> Wazuh shadow deployment -> human approval
```

Items tagged `[ROADMAP]` are designed but not implemented now (see Part 2).
Rule 8 in [AGENTS.md](../AGENTS.md) forbids implementing them unless the
maintainer explicitly asks.

## Part 1 — Hackathon scope (Oct 27 - Nov 4)

### 1. Alerts to ATT&CK chain

Deterministic correlation builds an entity graph over host, user, IP and
process within time windows. Correlated alerts become candidate incidents
mapped to MITRE ATT&CK techniques.

Severity is explainable, derived from three factors:

- ATT&CK stage (e.g. initial access vs. lateral movement vs. exfiltration),
- chain breadth (number of distinct entities and techniques),
- success vs. attempt (did the action succeed or only get attempted).

The deterministic score is mapped to OCSF `severity_id` (1 Informational
to 6 Fatal) and sets a floor: models may raise severity by at most one
level, only by citing validated evidence event ids, and may never lower
it below the floor. The database enforces the same cap
(`severity_floor` 1–6, `severity_id` between the floor and the floor
plus one); a human override path comes later. This cap also bounds
injection-driven severity inflation.

### 2. Glimmer reads raw evidence, Spark never does

Muse Glimmer (on-prem, vLLM, OpenAI-compatible) makes one structured call per
incident cluster: no tools, JSON-schema output, async batch queue with up to
16 in flight (~8 tokens/s per request, ~114 tokens/s at 16 concurrent
and ~196 tokens/s at 32, with linear scaling and no errors; roughly
1-1.5 min per cluster; never per-event synchronous calls). Because a
cluster can outlast the work queue's 60-second default lease, the
worker heartbeats the job while Glimmer runs (see the durable queue
under State below); losing the heartbeat means the worker stops and
writes no result.

Glimmer reads the raw evidence of each cluster and produces the condensed
incident that is pseudonymized for Spark. Raw logs are only ever seen by the
on-prem model.

Reasoning strength (`Reasoning strength: low|medium|high` in the system
message) is a per-purpose setting chosen by the evaluation harness, not by
cost alone: measured on Oct 27, more reasoning is not always more accurate,
and the model sometimes stops after reasoning with empty content
(`finish_reason` `"stop"`). The syntax validator treats empty content as a
failure: retry up to 3 attempts; if all are empty the cluster is stored as
`unprocessed` and escalated, never treated as benign. Default: medium,
`max_tokens` 4200. (Glimmer reasoning arrives in `message.reasoning`; vLLM
reports `reasoning_tokens` 0 although the tokens are counted in
`completion_tokens` — see token accounting below.)

### 3. Spark agent loop

Muse Spark (cloud API, `muse-spark-1.3`) runs a bounded agent loop over
pseudonymized incidents: max ~6 tool calls, token budget, timeout. Tools are
read-only and typed. Hackathon scope: two tools.

- `get_events` — query incident events (entity, time range, OCSF classes,
  limit <= 200). Only offers OCSF classes present in the source inventory
  (below). When a question needs an absent source, the model must report a
  visibility gap ("no network telemetry for this host"), never treat it as
  evidence of absence.
- `get_attack_technique` — look up a MITRE ATT&CK technique in the exact-key
  dictionary.

`[ROADMAP]` `get_entity_profile`, `search_sigma_rules`.
`propose_rule` is how the learning loop starts (Section 4).

Spark writes verdict, timeline and response plan in English or Spanish, citing
evidence event ids. Every Spark tool call is shown in a visible live trace
in the UI.

Model routing profiles: all-local (Glimmer only, nothing leaves the
network), hybrid (default: Glimmer local + Spark on pseudonymized
incidents), all-cloud (no GPU).

### 4. Rule -> backtest -> Wazuh shadow deployment (Linux plane)

Rules are developed against exported Wazuh archives of our lab attack chain,
then deployed in shadow to the live Wazuh. The loop:

1. Spark drafts a Sigma rule (`propose_rule`).
2. Deterministic verifier checks Sigma syntax, backtest (detects the target,
   zero false positives on the benign baseline, bounded scope) and evaluation
   cost. Before creating a rule, existing rules run on the evidence: if one
   fires, no new rule is created.
3. Shadow deployment: the rule runs on live data and logs would-be alerts
   without alerting.
4. Deployment to the customer SIEM requires human approval by default
   (approve/reject in the UI). Auto-deploy is optional and only for additive
   rules in shadow mode.

Sigma is the source format. Wazuh XML is generated from it (local rule id
range 100000-120000) and validated with `wazuh-logtest`. `[ROADMAP]`
Automatic promotion by deterministic gates, automatic rollback on alert-rate
misbehavior, rule dedup, per-technique/global quotas, usage-based TTL with
archiving, periodic consolidation, "modify the near-miss rule" flow, CDB
indicator lists (indicators go to expiring lists, never to rules).

Learning is additive only: exclusions, suppressions and allowlists always
require a human. Promotion is not a model tool.

### 5. Honest results table

Every reported number carries its `n`, time window and producing script
(e.g. `eval/run.py <args>`). False positives are the primary gate; detected
attack chains must not regress on any change to normalizers, correlation,
prompts or models. Dataset plumbing is implemented: `scripts/fetch_datasets.py`
downloads the pinned OTRF and EVTX-ATTACK-SAMPLES revisions into git-ignored
`data/`, verified against `datasets/checksums.txt`; `eval/ground_truth.py`
writes `data/ground_truth.json` (per-file `dataset` / `techniques` /
`tactics` / `label_source`; EVTX labels are tactic-level, linked OTRF
files are technique-level from metadata while unlinked ones carry
tactic-only `otrf-folder` labels). One compound exception is fetched at
the same OTRF pin: the APT29 day-1 host file (day 2, pcaps and Zeek are
not fetched). It carries no per-event labels, so it is evaluated at
chain level only and event-level precision cannot be computed on it:
`eval/apt29_day1_ground_truth.json` holds the ordered 10-step chain
from the pinned MITRE APT29 emulation plan, each step with its own
time window, lowercase anchors, the plan's technique ids
(`plan_techniques`), current ids resolved against ATT&CK v20.0
revoked-by relationships (`techniques`), any more-specific choice
recorded in `refinements`, and any deprecated plan id with no
replacement recorded as dropped. `eval/apt29_census.py` streams the
file, re-derives each window from anchor hits and reports the
difference, and computes each step's verdict (direct anchor evidence
in mapped events, indirect relevant events only, or none);
`eval/reports/apt29_day1_replay_load.md` is generated from it.
Dataset names, file names, technique ids, anchors and windows live
only in ground truth, eval code and provenance, never in OCSF records
or model inputs. Details: `datasets/README.md`.

### Supporting pieces (in scope)

- `corvus/llm/call.py` — single entry point for every model call (input
  guardrails, transport, validators, self-correction loop). Validators run in
  order: syntax (parseable JSON, non-empty content), schema (fields, types,
  enums), semantics (every cited `event_uid` belongs to the incident, every
  ATT&CK technique exists in the dictionary, pseudonyms valid, requested
  language), policy (verdict respects the deterministic floor, no broad
  exclusions in Sigma). Max 3 attempts: attempt 2 = same conversation plus
  structured errors; attempt 3 = escalated strategy (temperature 0, more
  reasoning, simplified schema). Stop early if the same error repeats twice.
  Then fall back to the other model per routing profile (always through the
  egress filter), then to the deterministic result marked "AI analysis
  failed". Tool-argument errors inside the agent loop return as observations;
  the loop applies to the final answer. Every attempt is recorded in
  `llm_attempts` with exact token counts: vLLM reports `reasoning_tokens` 0
  for Glimmer, so `call.py` requests `return_token_ids` and splits generated
  tokens by channel headers into reasoning, answer and overhead; provider
  usage is used as reported for Spark. Measured per model: first-pass
  validity, average corrections, final failure rate, correction cost.
  `[ROADMAP]` Circuit breaker, semantic canary, `model_health`
  (`corvus/llm/health.py`); prompt-injection classifier.
- Pseudonymizer with a stable `pseudonyms` table: the same entity always maps
  to the same pseudonym within a deployment, so chains stay correlatable
  after pseudonymization. Every Spark call goes through it.
- Egress filter before every Spark call: host allowlist (model endpoints,
  Wazuh only) plus a secret-pattern redactor (tokens, passwords in command
  lines). Network-level egress remains the operator's firewall; the HTTP
  client only talks to allowlisted hosts.
- Degraded mode (simple): deterministic detection keeps alerting; incidents
  wait as "pending AI analysis". A USD spend cap stops Spark calls near the
  limit (static `price_book` YAML maps models to per-token prices).
  `[ROADMAP]` Operating modes with schedules, "what would another model cost".
- Resume after being stopped: ingestion checkpoints (`search_after` cursors),
  durable work queue, persisted agent steps, plus a written summary so a new
  run continues instead of restarting.
- Injection as a signal: a detected injection attempt (deterministic pattern
  detector; `[ROADMAP]` classifier to be evaluated) becomes a signal of the
  incident itself and raises suspicion, while the severity-inflation cap
  (Section 1) bounds what injected content can achieve. Security-validator
  failures are never retried: quarantined, logged as security events.
- Reduced UI: FastAPI backend serving a React + TypeScript + Vite SPA.
  Views: incident list, timeline, ATT&CK chain, live agent trace, rules with
  shadow/active status and approve/reject, system health (lag, model latency,
  error/correction rate, spend). Live updates by polling (no SSE/WebSocket);
  server-side pagination for every list. `[ROADMAP]` Telegram and other
  notifiers.

### Interfaces, normalization, state

- `SiemAdapter` (Python `Protocol`) — the core depends only on this
  interface. No MCP between Corvus and Wazuh.
  - `stream_alerts(since cursor, page_size)` -> OCSF events, up to
    `page_size` (default 500, max 1000). Every event carries a stable,
    unique `metadata.uid`; ordering ties break on it and the cursor
    advances to the last returned event. Real adapters page on an
    ingestion-ordered key (`search_after`), never wall time alone, so
    late-indexed events are not skipped.
  - `query_events(entity, start, end, classes, limit<=200)`. Entity filters
    are strict: a provided field that canonicalizes to nothing raises, and
    `start` after `end` raises.
  - `translate_rule(sigma)` -> native rule; `validate_rule(native, samples)`;
    `deploy_rule(native, mode shadow|active)`; `rollback_rule(deployment)`.
  - `update_list(name, indicators, ttl)` `[ROADMAP]` (CDB indicator lists);
    real adapters raise `NotImplementedError` until it is in scope.
  - `describe_sources(window)` -> `SourceInventory`: what telemetry actually
    exists — per source: category (endpoint process, authentication,
    network, web/WAF, IPS, EDR, other), product/log source, OCSF classes,
    host count, event count, first/last seen. Grouped by the real telemetry
    source, never the index pattern; the category comes from an explicit
    source map, falling back to the OCSF class (`other` when unknown).
    Computed from the data, never configured by hand (Wazuh: aggregations
    over the indexer; replay: group-by over Parquet). Refreshed
    periodically; goes into the stable part of the Spark context
    (cache-augmented generation: identical prompt prefix — instructions,
    schemas, playbooks — first, variable incident last).
- `WazuhAdapter`: indexer REST API read-only for `wazuh-alerts-*` /
  `wazuh-archives-*`, polled with a `search_after` cursor stored as a
  checkpoint; server API with a limited role for logtest, rule files, CDB
  lists, config validation and manager restart.
- `ReplayAdapter`: public datasets normalized with `corvus replay load`
  into per-file events/provenance Parquet under `data/replay/`
  (explicit schemas, batched streaming, atomic writes) and queried
  with DuckDB; used by the evaluation harness. Directory loads skip
  bare JSON-lines files (some payloads ship zipped and bare
  byte-identical while metadata links only the archive; an explicitly
  named file still loads). Dataset paths and the in-band-technique
  flag live only in provenance, keyed by event uid for the harness
  ground-truth join, never in returned records. The rule surface is
  read-only until alert generation exists (rule methods raise
  `NotImplementedError`; Sigma matching in DuckDB will be
  case-insensitive, `ILIKE`, like Sigma itself).
  `[ROADMAP]` Splunk and Elastic adapters.
- Normalization: everything inside Corvus is OCSF (pinned v1.4.0; classes,
  activity ids, and attributes verified against the schema files,
  extensions such as win included, never written from memory). Classes:
  Authentication 3002, Process Activity 1007, Network Activity 4001, File
  System Activity 1001, Scheduled Job Activity 1006, Script Activity 1009,
  Registry Key Activity 201001, Registry Value Activity 201002, Windows
  Service Activity 201004 (all three from the win extension),
  Detection Finding 2004.
  All times UTC. Raw event kept on every record.
- State: PostgreSQL is the system of record — incidents, durable work queue
  (`SELECT ... FOR UPDATE SKIP LOCKED`), ingestion checkpoints, agent steps,
  rules with versions and lineage, analyst dispositions, budgets. No Redis.
  DuckDB is used only inside `ReplayAdapter`. The schema lives in
  `corvus/state/migrations/` as idempotent plain SQL: `0001` is migration
  bookkeeping (`schema_migrations`); `0002_core_tables.sql` creates the core
  tables — `checkpoints` (one row per adapter and stream, JSONB cursor),
  `work_queue`, `incidents`, `agent_steps`, `rules`, `dispositions`,
  `pseudonyms` (deployment-stable, so the same entity keeps its pseudonym
  across incidents and the UI can map back to real values), `spend`, and
  `llm_attempts`. All timestamps are `timestamptz` (`updated_at` is set
  by the application; there are no triggers). Partial indexes support the
  queue claim/lease queries, and composite indexes support the
  newest-first incident list filtered by status, AI status, and severity;
  `spend(created_at)` supports the daily budget sum. Crash-safe
  idempotency keys keep re-runs from duplicating work: the unique
  `incidents.correlation_key` for correlation and the nullable unique
  `work_queue.dedupe_key` for enqueueing. Analyst dispositions
  delete-restrict their incident and rule, so verdicts are never removed
  silently, and native rule ids stay inside the local 100000–120000
  range.
- Durable queue (`corvus/state/queue.py`, `WorkQueue` over `work_queue`;
  no migration beyond `0002` was needed). Delivery is at-least-once, so
  handlers must be idempotent. Enqueue takes an optional `dedupe_key`:
  the same key always returns the same job id and creates one row, and
  the key stays taken after the job is `done` or `dead`, so a
  deliberate re-run needs a new key (for example with a version or
  revision). Claim takes due `pending`/`failed` rows in
  `available_at`, then `id` order under a lease. Long handlers extend
  the lease with `heartbeat` at least every `lease / 3`; `heartbeat`,
  `complete`, and `fail` act only while the caller still owns an
  unexpired lock, so a stale worker cannot overwrite the new owner.
  `fail` retries with exponential backoff plus jitter and turns `dead`
  at `max_attempts`; reclaiming an expired lease also counts as an
  attempt (`last_error` `lease expired`) and turns `dead` at
  `max_attempts`, so a poison job that crashes its worker every time
  is not reclaimed forever. Every queue operation is one short
  transaction; no transaction is held open while a job runs.
- Knowledge: no vector RAG. Exact-key dictionaries (MITRE ATT&CK STIX,
  SigmaHQ rules, entity aliases, per-deployment baseline and allowlist).
- False positives: analyst disposition in the UI (true positive / false
  positive / benign authorized) is the primary signal; plus backtest on a
  historical window excluding incident entities, prevalence across hosts,
  periodicity, mass simultaneity, known context (human-maintained allowlist).
  `[ROADMAP]` Per-rule precision, daily alert budget (a rule over budget goes
  back to shadow), rule dedup/quotas/consolidation.
- Self-recovery, infrastructure layer: restart policies and watchers,
  healthchecks, timeouts, retries with exponential backoff, durable queue
  with heartbeated leases reclaimed after a crash (and dead-lettered
  after `max_attempts`), checkpoints, persisted agent steps,
  budget guard, degraded mode. `[ROADMAP]` Per-model circuit breaker, with
  coupling both ways: a high semantic failure rate opens the breaker even on
  HTTP 200, and a restarted model gets traffic only after a semantic canary
  (known-answer request, e.g. `sudo -> /bin/bash` maps to `T1548.003`) passes
  the validators. Transport errors never enter the semantic loop; semantic
  errors never restart processes.
- Deployment: Docker Compose (`corvus-api`, `corvus-worker`, `postgres`).
  Ports are published on 127.0.0.1 only (API `8000`, Postgres `55432`;
  host port 5432 belongs to another stack). Compose refuses to start
  without `CORVUS_ENV_FILE` pointing at a secrets file outside the
  repository; services read all secrets from that file, with no defaults.
  Glimmer runs on a separate GPU host, reached via `GLIMMER_BASE_URL`
  (required, no default).
- `[ROADMAP]` Raw Linux log parsers (auth.log, journald, auditd): Linux
  events arrive as Wazuh alerts and archives. `[ROADMAP]` Live Windows VM
  (lab currently uses exported/public data).

## Part 2 — Roadmap (designed, not implemented now)

Brief design notes. Do not implement (AGENTS.md rule 8).

- **Circuit breaker, semantic canary, `model_health`** (`corvus/llm/health.py`):
  per-model transport + semantic health. A high semantic failure rate opens
  the breaker even if the endpoint still answers HTTP 200; a restarted model
  receives traffic only after a canary with a known answer (e.g.
  `sudo -> /bin/bash` maps to `T1548.003`) passes the validators.
- **Prompt-injection classifier**: optional, to be evaluated against the
  deterministic pattern detector; a detection becomes an incident signal
  either way.
- **Operating modes with schedules**: all-local / hybrid / all-cloud plus
  time-based schedules, and "what would another model cost" estimates from
  the static `price_book`.
- **Telegram and other notifiers**: outbound incident notifications; additive
  to the UI, never a substitute for the durable queue.
- **Hunting in the residual**: Glimmer also reviews alerts not correlated
  into incidents, prioritized by deterministic anomalies.
- **Automatic promotion and automatic rollback**: promotion by deterministic
  gates (backtest, shadow precision, scope), rollback when a rule's alert
  rate misbehaves. Promotion is never a model tool.
- **Rule dedup, quotas and consolidation**: per-technique and global quotas,
  usage-based TTL with archiving, periodic consolidation of overlapping
  rules, per-rule precision with a daily alert budget (over budget returns
  the rule to shadow).
- **CDB indicator lists**: IP/hash/domain indicators go to expiring Wazuh CDB
  lists via `update_list`, never into rules.
- **Splunk and Elastic adapters**: new `SiemAdapter` implementations; the
  core stays interface-only.
- **Raw Linux log parsers**: auth.log, journald, auditd as direct sources
  for environments without Wazuh coverage.
- **Live Windows VM**: lab attack chains replayed live instead of from
  exported/public data.
