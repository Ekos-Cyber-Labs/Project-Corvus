# Corvus architecture

Corvus is NOT a SIEM. It is an AI SOC analyst that plugs into the SIEM the
organization already runs.

- The SIEM detects atomic events and stores logs. Corvus does not replace it.
- Corvus consumes SIEM alerts, queries the SIEM for context on demand
  (it does not re-ingest all logs), correlates alerts into attack chains
  deterministically, reasons over them with AI, hunts in what was not
  correlated, learns new detections, and pushes them back to the SIEM as rules.
- When a learned rule passes backtest and human approval, the customer's
  SIEM keeps that narrow detection even when Corvus is off. Gate 2 shows
  the current limit: one shadow rule covered 1 of 8 variant steps
  (n = 1 run, 1 rule, 1 variant;
  `eval/reports/gate2_variant_2026-11-01.md`).
- Hackathon scope: Wazuh only. Adapters for other SIEMs are roadmap.

Data flow (hackathon):

```
Wazuh alerts/archives -> SiemAdapter -> OCSF -> deterministic correlation + ATT&CK
  -> Glimmer triage (on-prem, raw evidence) -> condensed incident
  -> pseudonymizer -> Spark agent loop (pseudonymized only)
  -> Sigma rule proposal -> backtest -> Wazuh shadow deployment -> human approval
```

Items tagged `[ROADMAP]` are designed but not implemented now (see Part 2).
They are implemented one at a time on the `dev` branch when the maintainer
asks for them; an item's tag is removed in the same change that lands it.

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
`unprocessed` and escalated, never treated as benign. Default: medium
(`TRIAGE_REASONING_STRENGTH` in `corvus/llm/prompts/triage.py`), output cap
4500 tokens (`corvus/llm/config.py`). (Glimmer reasoning arrives in `message.reasoning`; vLLM
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

`[ROADMAP]` `get_entity_profile`. (`search_sigma_rules` exists as a
rule-loop-only tool; analysis never gains it.) `propose_rule` is how
the learning loop starts (Section 4).

Spark writes verdict, timeline and response plan in English or Spanish, citing
evidence event ids. Every Spark tool call is shown in a visible live trace
in the UI.

Model routing profiles: all-local (Glimmer only, nothing leaves the
network), hybrid (default: Glimmer local + Spark on pseudonymized
incidents), all-cloud (no GPU).

### 4. Rule -> backtest -> Wazuh shadow deployment (Linux plane)

Rules are developed against exported Wazuh archives of our lab attack chain,
then deployed in shadow to the live Wazuh. The loop
(`corvus/learning/propose.py`, CLI `corvus rules propose --incident ID`):

1. Spark drafts a Sigma rule over the condensed, pseudonymized incident,
   with three read-only tools: `get_events` (the same allowlisted tool
   analysis uses), `search_sigma_rules` (at most 8 shipped-corpus hits;
   rule-loop only, analysis never gains it) and `backtest_rule` (stable
   codes, counts and matched target uids only — never raw events).
2. At most 3 rounds of generate -> backtest -> correct with hard caps on
   tool calls, turns and tokens; every turn lands in `llm_attempts`
   (purpose `rule_proposal`) with that round's verifier codes, and billed
   turns land in `spend`. The model cites incident event uids it found
   itself; the final `RuleProposal` JSON (all properties required,
   nothing else accepted) must match the accepted round's YAML exactly.
   Selectors holding a registry pseudonym are rejected
   (`pseudonym_in_rule`); selectors keyed on attacker-controlled strings
   from the incident's injection signals are rejected
   (`attacker_literal`), including rules that depend on such a string
   without naming it contiguously (the verifier re-evaluates the rule
   with the token neutralized and rejects when the match disappears).
   A final output echoing injected content ends
   `rejected_unsafe` without retry and stores nothing.
3. An accepted rule is stored as `candidate` with lineage (source
   incident, cited uids — every one matched by the accepted backtest,
   accepted backtest with the SHA-256 of the exact evaluated text,
   rounds used, model, prompt version `rule_proposal/v1`, ledger ids,
   creation time). The store re-runs the backtest itself and never trusts
   a caller verdict. Outcomes:
   `accepted`, `exhausted`, `rejected_unsafe`, `budget_stopped`.
   Accepted residual: a single `NOT` of one literal of 4+ characters (for
   example a command name) is allowed by design; the reviewer sees it in the rule text.
4. Shadow (`corvus rules approve ID --to shadow --approver NAME --reason
   TEXT`, `corvus/learning/shadow.py`, approver restricted to
   `CORVUS_RULE_APPROVERS` when that comma-separated list is set):
   the rule runs through the same
   loader, engine and mapping as the shipped rules; matches become
   findings marked shadow (rule id, version, Sigma id) that are
   returned, never persisted to the findings store, so no notification
   fires and no incident severity changes. Hits bump the rule counter;
   operator `tp`/`fp` verdicts land in `dispositions`.
   `corvus rules rollback ID` silences a rule instantly;
   `LEARNED_RULES_ENABLED=0` disables all learned rules at once.
5. Deployment to the customer SIEM requires human approval by default.
   Auto-deploy is optional and only for additive rules in shadow mode.

The learning proof (`corvus rules prove`, `corvus/learning/proof.py`)
stores the golden stand-in, shows it fires on the control-variant
store while the detection adds zero `llm_attempts`/`spend` rows, and
shows the rolled-back rule silent. There is no fine-tuning anywhere:
what is learned is a verified, versioned rule.

Gate 2 (`corvus eval gate2`, `eval/gate2.py`) is the live-run
counterpart: two Wazuh exports of the unseen variant chain (rule
present vs rule absent) are loaded into temporary stores with the
existing Linux loader, and the report refuses to flatter. Anti-leak
checks come first (rule created before the first variant step, cited
events inside training windows and outside every variant window and
export, no variant-declared value in the detection text, recorded
model attempts all predating the variant — any failure is INVALID).
Cited-event timestamps resolve from the training replay store
(`--train-dir`, via the real evidence loader
`load_replay_events_by_uid`): neither the rule lineage nor the
incident row carries per-event times. A cited event outside every
`--train-gt` window is `lineage_outside_training_windows`; an
unresolvable cited uid is `lineage_event_unresolved`.
The positive export must show the rule's own `corvus_<sigma id>`
alerts on every `expected: detect` step and nowhere else (misses are
failures, expected-miss hits are surprises, out-of-window hits are
false positives); the negative export must show zero of them (a hit
there is contamination, hits only there mean swapped inputs); the
same rule must match zero baseline events through the same engine;
and the detection window (first variant step to last learned
finding, inclusive) must hold zero `llm_attempts`/`spend` rows while
later rows stay reported, never hidden. Ground-truth lines carry
`expected` (`detect` by default, `miss` where the rule should stay
silent — anything else refuses) and optional `variant_specific`
values. Output is `eval/reports/gate2.md` plus `gate2.json` (written by `corvus eval gate2` and not committed), every
number with window, n, producing command and git commit.

Sigma is the source format. A stored rule's Sigma id is assigned by
Corvus (fresh uuid4 rewritten into the stored text at store time;
the model's id is ignored so it can never collide) and its Sigma
status is always `experimental`; deployment lifecycle lives in the
row's `status` column (`candidate`/`shadow`/`active`), never in the
text. A first store is always version 1; a revision passes the
superseded rule id, reuses its Sigma id at version previous + 1, and
records the superseded id in lineage while the old row is kept.

Wazuh XML is generated from it (`corvus/learning/wazuh_xml.py`,
local rule id range 100000-120000) and validated with
`wazuh-logtest`. Shadow-mode flow:

1. `candidate -> approved to shadow` (human approver + reason;
   the approver must be listed in `CORVUS_RULE_APPROVERS` when set).
2. `corvus rules export-wazuh ID --out DIR` writes the `<group>`
   block for `local_rules.xml` (one rule per source: sudo matching
   the decoded `command` field, auditd matching `full_log`), the RAW
   `full_log` lines of the backtest target events plus a documented
   baseline sample (every plausible-match same-decoder line plus a
   capped context sample, resolved through replay provenance),
   `expected.json` with the Sigma engine's own must-fire flags, and
   a plain-text deploy plan.
3. The operator pastes the group into `local_rules.xml`, runs
   `wazuh-analysisd -t`, restarts the manager. Sibling precedence:
   the first matching sibling under a decoder group wins, so each
   rule hangs under the group root and every stock sibling that
   could match first (computed from the shipped ruleset, e.g. sudo
   under 5400/5401/5402/5407/5403/5405/5406). A matching child
   replaces its parent's alert, so each shadow rule sits at the
   highest level among the parents it replaces (never below an
   existing alert; floored below `log_alert_level` for level-0-only
   chains, which stay archives-only). The shadow check: alerts for
   these events are unchanged in count and level, now carrying the
   `corvus_shadow` group.
4. `corvus rules logtest ID --bundle DIR` feeds the lines through
   `wazuh-logtest` (bridge contract: one JSON line per event in,
   one out with the `decoder` and `rule` blocks; the command to
   reach the manager comes only from `CORVUS_WAZUH_LOGTEST_CMD`,
   never from code or the bundle) and writes the per-line
   Sigma-vs-Wazuh parity report with every disagreement listed.
5. Promotion raises both rules to level 7 (`active`, replacing the
   parent's alert with its own at the higher level); rollback
   removes the group, re-tests, restarts.

Translator limits (anything else is a typed refusal, never partial
output): `linux/process_creation` only; fields `CommandLine` and
`Image` only; modifiers `contains`/`startswith`/`endswith`/`all`
and plain equality (`|re` is always refused); selections joined by
`and`/`or` with at most one narrow negation (exactly one literal of
4+ effective characters, never `|re`); auditd `CommandLine` only as
`contains` (prefix/suffix/equality have no `full_log` form);
literals need 4+ effective characters, no control characters, and a
bounded pattern cost. Auditd hex-encoded arguments match only in
`full_log`, so every literal matches as plain text or uppercase hex
(case-insensitively); `Image` matches the decoded `exe`. Two native
ids per stored rule (the stored id plus the next free id above it).
The logtest parser relies only on the `decoder`/`rule` JSON blocks
(the archive/alert shape) and fails closed on anything else.

`[ROADMAP]`
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
  `[ROADMAP]` Circuit breaker, semantic canary, model health (no module
  exists yet: there is no `corvus/llm/health.py`); prompt-injection classifier.
- Pseudonymizer with a stable `pseudonyms` table: the same entity always maps
  to the same pseudonym within a deployment, so chains stay correlatable
  after pseudonymization. Every Spark call goes through it. For cloud
  payloads `prepare_payload` also drops every `raw_data` field (raw logs
  stay on-prem; the typed OCSF fields carry the evidence), scans all
  remaining free text for entity-shaped spans (IP literals, e-mails,
  FQDNs, UNC and `DOMAIN\user` forms, profile and home paths, command
  user arguments) and replaces each hit, after the caller registers the
  incident's typed entities — so a name typed in one event is hidden in
  another event's free text. Registered entities additionally match
  across percent-escapes, `_`/`-` joins, non-canonical IPv4 spellings
  (padded, spaced, hex) and inside dict keys; base64 blobs (UTF-8 or
  UTF-16LE, 24+ characters) decoding to a registered entity are
  replaced wholesale, as are even-length runs of 12+ hex digits
  (either case, the shape auditd emits for spaced arguments) decoding
  to one; decimal-integer IPv4 literals and JSON integers holding the
  packed 32-bit value of a registered IP map to the same IP
  pseudonym. Bare words in no recognizable position
  cannot be found deterministically. Remaining limit, by design:
  compressed or encrypted payloads, other charsets and short or
  binary hex stay verbatim, so a novel encoding of an entity is a
  known residual leak path.
- Egress filter before every Spark call: host allowlist (model endpoints,
  Wazuh only) plus a secret-pattern redactor (tokens, passwords in command
  lines). Network-level egress remains the operator's firewall; the HTTP
  client only talks to allowlisted hosts.
- Degraded mode (simple): deterministic detection keeps alerting; incidents
  wait as "pending AI analysis". A USD spend cap stops Spark calls near the
  limit (static `price_book` YAML maps models to per-token prices). All
  billed model calls must reserve before the call and convert after it.
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
  server-side pagination for every list. `[ROADMAP]` Chat and webhook
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
- `WazuhAdapter` (`corvus/adapters/wazuh/`, read-only): the indexer
  REST client pages `wazuh-alerts-4.x-*` with `search_after` on the
  stable sort `[timestamp, _id]` inside one point in time per call
  (the archive `id` repeats, so only `_id` orders without skipping),
  re-reads a 120 s overlap window behind the cursor dropping only
  records whose uid is already in the cursor's seen set, and persists
  the cursor in `checkpoints` (adapter `wazuh`, stream `alerts`) as
  the last time plus the window's `(time, uid)` pairs; checkpoint
  load failures raise instead of re-reading from the beginning.
  `wazuh-archives-4.x-*` serves entity/time-window queries (agent
  name, `data.srcuser`/`dstuser`/`srcip`) and the inventory
  aggregation (a second cheap alerts aggregation marks which decoders
  have findings). TLS is always verified (`WAZUH_INDEXER_CA`, no off
  flag) through an `ssl.SSLContext` that clears only
  `VERIFY_X509_STRICT`, which a stock Wazuh root CA (no Key Usage /
  Authority Key Identifier) otherwise trips; chain and hostname
  checks stay on. Only search, PIT open/close and the read endpoints
  used are allowlisted by strict index regex, with bounded retries on
  429/5xx only. Mapping (`corvus/normalize/wazuh.py`): alerts to
  Detection Finding 2004 plus the decoded event (sshd, sudo, auditd
  SYSCALL only, `syscheck_new_entry` / `syscheck_integrity_changed` /
  `syscheck_deleted`; the rest counted per decoder and rule id;
  `auid` 4294967295 falls back to `uid`). Source authority when
  `data` and `full_log` disagree: the log line wins wherever the
  Wazuh decode could be forged from attacker-controlled text --
  sshd user/peer (patterns anchor at the message start and parse
  right to left; differing decoded values are kept in
  `unmapped["linux.decoder_conflict"]`), the auditd EXECVE command
  line, file paths and `USER_CMD` user/command. Decoded `data` wins
  where the value is kernel-attributed (auditd auid/uid) and for
  sudo, whose mapper reads only the decoded fields (invoking user,
  target user, command come from the pre-command header, ahead of
  the attacker-controlled COMMAND text). Rule translation, backtest
  and deployment stay `NotImplementedError` for the shadow-deployment
  milestone; server API with a limited role for logtest, rule files,
  CDB lists, config validation and manager restart.
- Live poll (`corvus wazuh poll [--once | --interval SECONDS]`, no model
  calls on this path): reads new alerts through
  `WazuhAdapter.stream_alerts` (settings from `WAZUH_INDEXER_URL` /
  `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` /
  `WAZUH_INDEXER_CA` only; TLS verification stays on; credentials
  never appear in logs, errors, argv, or the database), keeps its
  cursor in the `checkpoints` table (resumable after a crash, overlap
  handled, idempotent by document id), normalizes with the alert-hit
  mapper, writes events and findings into a live replay-format store
  (`--store`, default `data/live`; provenance is the index name plus
  the document id instead of a file and line), correlates the store
  into incidents and upserts them. Findings come from each alert's
  own rule block; the Sigma engine over live events stays out of this
  path. Bounded per cycle: page size (`--page-size`, max 1000), max
  documents (`--max-docs`), backoff with jitter on indexer errors, a
  hard 30 s read timeout per request, clean stop on SIGINT/SIGTERM.
  `--with-archives` fetches the surrounding raw events for the host
  and time window of each new incident via `query_events` (capped by
  `--archives-limit`) so the analysis loop's `get_events` has
  context; the cycle reports how many were added and says plainly
  when the archives index returns nothing. Correlation windows come
  from `CORRELATION_SESSION_GAP_MINUTES` /
  `CORRELATION_MAX_SPAN_HOURS` /
  `CORRELATION_AUTH_FAILURE_THRESHOLD` (else the correlate
  defaults), so the poll never requires model settings to run.
  Learned-rule attribution (`corvus/live/attribution.py`): a finding
  is a learned-rule finding ONLY when its alert carries a Corvus
  group (`corvus_shadow`, `corvus_active` or `corvus_<sigma id>`) —
  sites commonly keep their own custom rules in 100000-120000, so a
  bare in-range id is a normal finding. Past the gate the native id
  and the Sigma groups must agree on one stored row (a sudo/auditd
  pair joins by its shared `corvus_<sigma id>` group when the
  pair-secondary id is unstored but in range); anything else with a
  Corvus group is `unknown_learned_rule`. The incident and the
  finding carry the reference (rule record id, Sigma id, version,
  mode shadow/active, lineage id), exposed read-only in the incidents
  API. Shadow findings (group `corvus_shadow`) never raise incident
  severity, never notify (no notification path exists), and read
  visibly different through that reference; an `unknown_learned_rule`
  is kept, flagged, never trusted, never raising severity. Every
  cycle writes one `wazuh_poll_cycles` row
  (counts only, including learned/shadow/unknown findings), and
  `corvus rules ledger-check --start ISO --end ISO [--expect-zero]`
  prints the `llm_attempts`/`spend` rows of a window grouped by
  purpose and model (non-zero exit with `--expect-zero` when any
  exist), so the no-model proof never depends on log scraping.
  The operator reaches the indexer through a local port forward to
  the manager host; the forward command and any address stay outside
  the repository (local shell / env file only, never committed).
- Automatic sweep (`corvus sweep [--once | --interval SECONDS]`,
  default every 300 s, minimum 30): each cycle reuses the live poll
  above (same `wazuh_poll_cycles` ledger row, linked by
  `sweep_runs.poll_cycle_id`), selects the incidents the cycle created
  or grew whose `ai_status` is still pending, and runs the existing
  analysis on the ones the pure `decide` policy picks (floor at or
  above `SWEEP_MIN_FLOOR`, or an injection signal with
  `SWEEP_ALWAYS_INJECTION`; ranked floor-first, capped at
  `SWEEP_MAX_ANALYSES` per cycle; past `SPEND_CAP_USD` everything is
  `skipped_budget`). Selection runs the Glimmer triage worker then
  `run_analysis` exactly as `corvus analyze` does, on a
  `ThreadPoolExecutor` with `SWEEP_TRIAGE_WORKERS` threads (default 4,
  1..16; 1 is sequential): decisions and submission order stay
  deterministic, only completion order varies, each task opens its
  own database connections, re-checks recorded spend plus a per-task
  spend hold right before its model calls (a task finding the cap
  reached calls no model and is recorded `skipped_budget`, bounding
  overshoot to one hold), and one task's exception never cancels the
  others. One incident's failure never stops the cycle, resolved
  analyses are never re-run, a `busy` claim is recorded
  `skipped_policy`/`already_running` instead of analyzed twice,
  and one Postgres advisory lock keeps two sweeps from overlapping.
  SIGINT/SIGTERM stop submitting new tasks while running ones finish
  within a bounded grace time, and the cycle log line prints elapsed
  seconds and the worker count.
  Sweep rows (`sweep_runs` plus per-incident `sweep_decisions`,
  migration `0013_sweep_runs.sql`) carry counts and the effective
  policy only — no credentials, raw events, or model text — and three
  read-only routes expose them: `GET /api/dashboard` (totals with
  `analyzed` meaning resolved analyses only, 24 hourly `first_seen`
  buckets anchored to now or to the latest data with
  `window.anchored_to`, sweep markers for the same window, five most
  recent resolved analyses), `GET /api/sweep/status` (last run, next
  estimate from last start plus stored interval, running flag, last
  policy), and `GET /api/settings` (effective policy, redacted
  `scheme://host[:port]` connection states with model addresses from
  `corvus.llm.config`, spend cap, versions). Evidence defaults to the
  poll store (`--replay-dir` falls back to `--store`); attempts derive
  as `analyzed + failed_analyses` with no new column; post-start
  failures record `failed` with the class name and stale `running`
  rows become `failed`/`abandoned`. The
  sweep never proposes, deploys, or approves rules, so the shadow and
  approval guarantees are unchanged.
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
  `[ROADMAP]` Adapters for other SIEMs.
- Normalization: everything inside Corvus is OCSF (pinned v1.9.0; classes,
  activity ids, and attributes verified against the schema files,
  extensions such as win included, never written from memory). Classes:
  Authentication 3002, Process Activity 1007, Network Activity 4001, File
  System Activity 1001, Scheduled Job Activity 1006, Script Activity 1009,
  Module Activity 1005, Registry Key Activity 201001, Registry Value
  Activity 201002, Windows Service Activity 201004 (the last three from
  the win extension, declared in `metadata.extensions`),
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
  `llm_attempts`; `0003_severity_factors.sql` records the severity factors
  behind each floor; `0004_llm_audit.sql` adds the audit-only nullable
  `llm_attempts.reasoning` (stays on-prem) and `token_source`
  (`exact_ids` / `usage` / `estimated`), the `incident_analyses` table
  (one row per incident and stage, `triage` / `analysis`), and
  `spend_reservations` for the USD budget guard. All timestamps are
  `timestamptz` (`updated_at` is set
  by the application; there are no triggers). Partial indexes support the
  queue claim/lease queries, and composite indexes support the
  newest-first incident list filtered by status, AI status, and severity;
  `spend(created_at)` supports the daily budget sum. Crash-safe
  idempotency keys keep re-runs from duplicating work: the unique
  `incidents.correlation_key` for correlation and the nullable unique
  `work_queue.dedupe_key` for enqueueing. Analyst dispositions
  delete-restrict their incident and rule, so verdicts are never removed
  silently, and native rule ids stay inside the local 100000–120000
  range; `0008_live_poll.sql` adds the read-only
  `incidents.learned_rules` attribution array and the per-cycle
  `wazuh_poll_cycles` bookkeeping table;
  `0009_rules_sigma_version.sql` keeps one row per (Sigma id, version);
  `0010_poll_cycle_status.sql` closes poll cycle rows as `failed` with the
  exception class and counts future-dated alerts; `0011_agent_step_emitted.sql`
  persists per-step emitted pseudonyms for the analysis verdict scope;
  `0012_pseudonym_counters.sql` allocates pseudonym numbers from monotonic
  per-kind counters so deleted rows never reuse a number.
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

Brief design notes. Implemented one at a time on `dev` when the maintainer
asks for them.

- **Circuit breaker, semantic canary, model health** (roadmap, no module exists yet: there is no `corvus/llm/health.py`):
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
- **Chat and webhook notifiers**: outbound incident notifications; additive
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
- **Adapters for other SIEMs**: new `SiemAdapter` implementations; the
  core stays interface-only.
- **Raw Linux log parsers**: auth.log, journald, auditd as direct sources
  for environments without Wazuh coverage.
- **Live Windows VM**: lab attack chains replayed live instead of from
  exported/public data.
