# AGENTS.md

Project Corvus is an on-prem AI SOC analyst for small teams with no 24/7 SOC that cannot ship logs to a vendor cloud.
It was built during the Meta Global AI Developer Hackathon (Oct 27 - Nov 4, 2026). All product code is written in that window, so keep commit history honest.

## Pipeline

Sources (Wazuh alerts/archives, Windows EVTX/Sysmon, Linux auth.log/journald/auditd) go through normalizers into OCSF events and a store.
Deterministic correlation (host, user, IP, process, time window) plus MITRE ATT&CK mapping produces candidate incidents.
On-prem Muse Glimmer triages via an async batch queue, then a pseudonymizer runs before Muse Spark reasoning.
Muse Spark returns verdict, timeline, response in English or Spanish, and tool calls into the store.
Proposed Sigma and Wazuh XML rules are backtested against the data and need human approval.
A web UI and an eval harness against ground truth sit alongside this.

## Layout (proposed)

- `corvus/connectors` — source ingestion.
- `corvus/normalize` — source-specific normalizers to OCSF.
- `corvus/store` — event and incident storage.
- `corvus/correlate` — deterministic correlation and ATT&CK mapping.
- `corvus/llm` — clients, prompts, JSON schemas, pseudonymizer.
- `corvus/rules` — proposed detection rules and backtesting.
- `corvus/api` — API backing the UI.
- `ui/` — web UI.
- `eval/` — eval harness and ground truth.
- `lab/` — reproducible Atomic Red Team chains with expected techniques and time windows.
- `tests/` — automated tests.

## Commands

TODO until the skeleton exists. Do not invent commands.

## Hard rules

1. Use only public datasets (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES, AIT Log Data Set) or our own lab data. Never use real customer logs, company names, or people.
2. Never commit datasets. Use download scripts with checksums and license notes. Fixtures use RFC 5737 IPs and `example.com`.
3. Read secrets only from environment variables such as `META_API_KEY`. Never put secrets in code, fixtures, logs, or test output.
4. Send Muse Spark only condensed, pseudonymized incidents. Raw events never leave the on-prem path. Every Muse Spark call goes through the pseudonymizer.
5. Keep correlation and scoring deterministic and explainable. Models triage, summarize, and narrate; they never silently decide scores.
6. Run the eval harness for any change to normalizers, correlation, prompts, or models, and report the metric delta. False positives are the primary gate; detected attack chains must not regress.
7. Agents never commit, amend, or push. The maintainer commits.

## Models

Clients are OpenAI-compatible. Switching models is `base_url` plus model name.
- On-prem triage: Muse Glimmer 30B, FP8 on vLLM, served as model `glimmer` at `GLIMMER_BASE_URL` (default `http://127.0.0.1:8001/v1`).
- Reasoning: `muse-spark-1.3` at `META_BASE_URL=https://api.meta.ai/v1` with `META_API_KEY`.
- Both models reason by default and reasoning tokens count against `max_tokens`. A low limit returns HTTP 200 with null content. Use `max_tokens >= 1500` and treat empty content as an error.
- Glimmer reasoning arrives in `message.reasoning`. vLLM reports `reasoning_tokens` 0 even though the tokens are counted in `completion_tokens`.
- Set Glimmer depth in the system message; triage uses `Reasoning strength: low`.
- Glimmer does about 7 tokens/s per request and about 70 tokens/s at 16 concurrent, roughly 1-1.5 min per cluster. Keep triage as an async batch queue with up to 16 in flight, never per-event synchronous calls.
- Validate all model output as JSON against a schema. Retry once, then record a failure in the eval.

## Conventions

- Use Python 3.12 with type hints and small modules.
- Write code, comments, and docs in English.
- Use OCSF classes 3002 Authentication, 1007 Process Activity, 4001 Network Activity, 1001 File System Activity, 1006 Scheduled Job Activity, and 2004 Detection Finding. Keep the raw event attached to every OCSF record.
- Ship every normalizer with a fixture-based test.
