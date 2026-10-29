# AGENTS.md

> 👋 Yes, this file is supposed to be here. It's the rulebook our AI coding agent (Muse Code) reads before touching anything, committed on purpose so hackathon judges can see exactly how Corvus was built. No secrets
were harmed in the making of this file.

Project Corvus is an on-prem AI SOC analyst for small teams with no 24/7 SOC that cannot ship logs to a vendor cloud.
It was built during the Meta Global AI Developer Hackathon (Oct 27 - Nov 4, 2026). All product code is written in that window, so keep commit history honest.

Corvus is NOT a SIEM. It plugs into the SIEM the organization already runs (Wazuh in hackathon scope): the SIEM detects atomic events and stores logs; Corvus consumes SIEM alerts through a `SiemAdapter`, queries the SIEM for context on demand, correlates alerts into attack chains deterministically, reasons over them with AI, and pushes learned rules back to the SIEM. Full design: `docs/architecture.md`. Threat model: `docs/threat-model.md`.

## Pipeline

Linux events arrive as Wazuh alerts and archives (no raw log parsing in hackathon scope). Windows coverage comes from Wazuh agents and public EVTX datasets via replay.
Alerts flow through the adapter into OCSF events; there is no local event store — PostgreSQL is the system of record (incidents, queue, checkpoints, agent steps, rules, dispositions, pseudonyms, spend, LLM attempts, budgets; migration `0002_core_tables.sql`), and the SIEM remains the log store queried on demand.
Deterministic correlation (host, user, IP, process, time window) plus MITRE ATT&CK mapping produces candidate incidents with an explainable severity floor; the database keeps `severity_id` within one level above the floor, and unique `correlation_key` / queue `dedupe_key` values keep crash re-runs from duplicating incidents or jobs.
On-prem Muse Glimmer triages each cluster via an async batch queue (it alone sees raw evidence), then a pseudonymizer runs before Muse Spark reasoning.
Muse Spark runs a bounded agent loop (`get_events`, `get_attack_technique`) and returns verdict, timeline, response in English or Spanish.
Proposed Sigma rules are backtested, deployed to Wazuh in shadow mode, and need human approval.
A reduced web UI and an eval harness with an honest results table (every number carries n, window, producing script) sit alongside this.

## Layout

- `corvus/adapters` — `siem.py` interface, `wazuh/`, `replay/`.
- `corvus/normalize` — OCSF models and mappers.
- `corvus/state` — Postgres schema, migrations, queue.
- `corvus/correlate` — deterministic correlation and ATT&CK mapping.
- `corvus/llm` — clients, prompts, schemas, agent loop (`call.py`).
- `corvus/guardrails` — validators, pseudonymizer, egress filter.
- `corvus/learning` — rule generation, verification, shadow, promotion, lifecycle.
- `corvus/api` — API backing the UI.
- `ui/` — web UI.
- `eval/` — eval harness and ground truth.
- `lab/` — reproducible Atomic Red Team chains with expected techniques and time windows.
- `tests/` — automated tests.

## Commands

- `make install` — install dependencies with uv (dev group included).
- `make lint` — ruff check, ruff format check, mypy.
- `make test` — full pytest; the migration integration test always runs and
  refuses anything but `DATABASE_URL=postgresql://...@127.0.0.1:55432/corvus_test_<name>`
  (wrong port or database prefix fails, never skips). Test env recipe:
  reuse `/tmp/corvus-test.env` and the existing Compose volume when they
  exist (never overwrite the env file, never `docker compose down -v`),
  `CORVUS_ENV_FILE=/tmp/corvus-test.env docker compose up -d postgres`,
  `DATABASE_URL=postgresql://corvus:<pw>@127.0.0.1:55432/corvus_test_<rand> UV_CACHE_DIR=/tmp/uv-cache make test`,
  `CORVUS_ENV_FILE=/tmp/corvus-test.env docker compose down`
  (`UV_CACHE_DIR=/tmp/uv-cache` prefixes every `make` and `uv` command:
  the sandbox forbids writes to `~/.cache/uv`).
- `make up` / `make down` — start / stop `postgres`, `corvus-api`, `corvus-worker`;
  both require `CORVUS_ENV_FILE` set (compose fails fast otherwise).
- `corvus version` — print the package version.
- `corvus db migrate` — apply pending SQL migrations (reads `$DATABASE_URL`).
- `CORVUS_ENV_FILE=/path/outside/repo.env docker compose up --build` — secrets
  come from the file outside the repository, never from committed files.

## Hard rules

1. Use only public datasets (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES) or our own lab data. Never use real customer logs, company names, or people.
2. Never commit datasets. Use download scripts with checksums and license notes. Fixtures use RFC 5737 IPs and `example.com`.
3. Read secrets only from environment variables such as `META_API_KEY`. Never put secrets in code, fixtures, logs, or test output.
4. Send Muse Spark only condensed, pseudonymized incidents. Raw events never leave the on-prem path. Every Muse Spark call goes through the pseudonymizer.
5. Keep correlation and scoring deterministic and explainable. Models triage, summarize, and narrate; they never silently decide scores.
6. Run the eval harness for any change to normalizers, correlation, prompts, or models, and report the metric delta. False positives are the primary gate; detected attack chains must not regress.
7. Agents never commit, amend, or push. The maintainer commits.
8. Do not implement anything under Roadmap in docs/architecture.md unless the maintainer explicitly asks.
9. .agents/MEMORY.md is committed to a public repository. Write in it only what could appear in the README: no IP addresses or hostnames of real infrastructure, no personal names, no secrets or key names with values, no paths outside this repository, no lab credentials, no content from datasets beyond file counts. Before writing to .agents/MEMORY.md, re-read this rule. The legends in AGENTS.md, .agents/MEMORY.md and .agents/README.md must be kept verbatim.

## Models

Clients are OpenAI-compatible. Switching models is `base_url` plus model name.
- On-prem triage: Muse Glimmer 30B, FP8 on vLLM, served as model `glimmer` at `GLIMMER_BASE_URL` (required, no default).
- Reasoning: `muse-spark-1.3` at `META_BASE_URL=https://api.meta.ai/v1` with `META_API_KEY`.
- Both models reason by default and reasoning tokens count against `max_tokens`. A low limit returns HTTP 200 with null content. Use `max_tokens >= 1500` (Glimmer default 4200) and treat empty content as an error.
- Glimmer reasoning arrives in `message.reasoning`. vLLM reports `reasoning_tokens` 0 even though the tokens are counted in `completion_tokens`; `call.py` requests `return_token_ids` and splits generated tokens by channel headers, so `llm_attempts` carries exact counts.
- Set Glimmer depth in the system message. Reasoning strength (`low|medium|high`, default medium) is a per-purpose setting chosen by the evaluation harness, not by cost alone.
- Glimmer does about 8 tokens/s per request, about 114 tokens/s at 16 concurrent and about 196 tokens/s at 32, with linear scaling and no errors, roughly 1-1.5 min per cluster. Keep triage as an async batch queue with up to 16 in flight, never per-event synchronous calls.
- All model output is validated by the self-correction loop in `corvus/llm/call.py`: validators run in order (syntax, schema, semantics, policy, security); on failure the output is discarded and the model is re-asked with a structured error, up to 3 attempts (attempt 3 escalates: temperature 0, more reasoning, simplified schema), then falls back to the other model per routing profile, then to the deterministic result marked "AI analysis failed". Security failures are never retried. Every attempt is recorded in `llm_attempts` and measured in the eval.

## Roles

Project-local skills under `.agents/skills/`:

- `platform-engineer` — skeleton, packaging, Compose, Postgres, queue, API plumbing, config, health.
- `detection-engineer` — adapters, normalizers, correlation, ATT&CK mapping, Sigma to Wazuh XML.
- `llm-engineer` — clients, prompts, schemas, Glimmer queue, Spark agent loop, routing, pseudonymizer.
- `security-reviewer` — threat model, guardrails, injection, egress, secrets, UI safety, rule poisoning.
- `eval-engineer` — harness, ground truth, metrics, train/test split, reports.
- `frontend-engineer` — React + Vite UI served by FastAPI.

Every prompt names the role it works under. Changes under `corvus/llm`, `corvus/guardrails`, `corvus/learning`, `corvus/api`, or `ui/` finish with a `security-reviewer` pass.

## Conventions

- Use Python 3.14 with type hints and small modules.
- Write code, comments, and docs in English.
- Use OCSF classes 3002 Authentication, 1007 Process Activity, 4001 Network Activity, 1001 File System Activity, 1006 Scheduled Job Activity, 1009 Script Activity, 1005 Module Activity, 201001 Registry Key Activity, 201002 Registry Value Activity, 201004 Windows Service Activity, and 2004 Detection Finding. Keep the raw event attached to every OCSF record.
- OCSF classes, activity ids and attributes are verified against the pinned v1.9.0 schema files (including extensions such as win) before use, never written from memory.
- Ship every normalizer with a fixture-based test.
- Every version pin (schema, runtime, image, dependency, dataset commit, rule release) is the latest stable release when it is pinned, checked against the upstream release list and recorded with the date. An older pin needs a written reason. Release candidates are not pinned.

## Working agreements

- One small module per prompt with input/output types and edge cases named.
- A hand-written fixture before the code; tests derived from it.
- No new dependencies, no ORM, no invented commands.
- For any library whose API you are not certain of (pySigma, python-evtx/evtx in particular), inspect the installed package API and run a minimal check before using it; never write API names from memory.
- Always paste the actual test and lint output; never claim success from reading code.
- Integration tests must actually run in this development environment: if Postgres or another dependency is unreachable, stop and say so instead of reporting skipped tests as success.
- If Postgres rejects the connection, stop and report it; do not continue with the Postgres tests failing.
- Report any failing or erroring test at the top of the reply; never record a run as verified in `.agents/MEMORY.md` unless the full suite passed with Postgres.
- End every reply with a checklist mapping each deliverable and each report item the prompt asked for to the file and section where it is, or to `missing` with why.
- Every emitted OCSF record passes the conformance test; a new class or object is added to it in the same change.
- Changes to normalizers, correlation, or prompts report the eval delta.

## Review lessons

- Date `.agents/MEMORY.md` entries with the maintainer's local date
  (UTC-6), not the sandbox clock, which runs in UTC.
- Leave the compose Postgres in the state you found it (do not stop
  or remove it after the tests).

## Known pitfalls (check before finishing)

- Graceful shutdown on SIGTERM.
- Lease expiry races and idempotent job handling.
- Bounded queues.
- Backoff with jitter.
- Timezone-aware UTC datetimes.
- Null vs missing fields.
- XML namespaces.
- Parquet types.
- SKIP LOCKED ordering and short transactions.
- Idempotent migrations.
- Streams always closed.
- Tool loops bounded.
- Strict JSON validation.
- Secrets never logged.
- Prompts assembled with delimited, escaped untrusted data.
- No timing-dependent tests.
- Fakes at the HTTP boundary instead of deep mocks.
- UI without effect loops or stale closures.
- Every filter rejects placeholder, empty, and wrong-type values instead of matching everything.
- Every paged query orders by a unique, stable tie-breaker.
- Every invalid or out-of-root path raises instead of falling back silently.
- Every premise about real data was checked against real data before use.
- Docstrings, comments and docs make only claims checked against the code or the data, like reported numbers.
- Every documented command was run exactly as written.
- Every reported number names what it counts and reproduces from a committed script.
- `# noqa` only for a rule the project's ruff config actually selects.
- Work only inside this repository, its git-ignored `data/` and `/tmp/corvus-test.env`: never search or read the rest of the filesystem (no `find /`, no other users' or tools' directories under `/tmp`, `/private/tmp`, `/System/Volumes` or the home directory), and never use files not fetched through `scripts/fetch_datasets.py` (a needed reference is fetched, pinned and checksummed into `data/`, never picked up from a copy found on disk; copies outside the repository left by earlier sessions, for example `/tmp/ocsf-1.9.0`, are not used).
- Each prompt adds its own dated entry to `.agents/MEMORY.md`, written after the final test run.
- Report dates use the maintainer's local date.
- No dead aliases, fallbacks, or shims are left behind.
- Every file changed outside the prompt's scope is listed in the reply.
- Tool and linter pins match across every config that sets them.
