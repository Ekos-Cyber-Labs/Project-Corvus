# Project Corvus

An on-prem AI SOC analyst that turns thousands of security alerts into a few explained attack chains, without logs leaving your network.

## The problem

Small companies run Linux servers and Windows endpoints, often with Wazuh as their only security tool and no 24/7 SOC. Existing AI SOC tools are enterprise-priced SaaS that require shipping raw logs to a vendor cloud. Real attacks stay buried in uncorrelated alerts.

## How it works

Corvus is not a SIEM. It plugs into the SIEM the organization already runs (Wazuh): the SIEM detects atomic events and stores logs; Corvus consumes alerts, correlates them into attack chains, reasons over them, and pushes learned rules back. Design: `docs/architecture.md`. Threat model: `docs/threat-model.md`.

- Consume Wazuh alerts and archives through a `SiemAdapter` (paged `stream_alerts` with stable per-event uids, strict entity filters, source-grouped inventory); Linux events arrive as Wazuh data, Windows coverage via Wazuh agents and public EVTX datasets through replay. No raw log parsing in hackathon scope.
- Normalize into OCSF events. No local event store: PostgreSQL is the system of record (checkpoints, work queue, incidents, agent steps, rules, dispositions, pseudonyms, spend, and LLM attempts; migration `0002_core_tables.sql`) and the SIEM stays the log store, queried on demand.
- Correlate deterministically by host, user, IP, process, and time window, map to MITRE ATT&CK, and set an explainable severity floor (the database keeps `severity_id` within one level above the floor).
- Triage each cluster on-prem with Muse Glimmer through an async batch queue. Glimmer alone sees raw evidence.
- Pseudonymize condensed incidents before any external reasoning call.
- Reason with Muse Spark in a bounded agent loop (`get_events`, `get_attack_technique`) for verdict, timeline, and response in English or Spanish.
- Draft Sigma rules, backtest them, deploy to Wazuh in shadow mode, and wait for human approval.
- Review incidents in the web UI and check changes with the eval harness.

```
Wazuh alerts/archives -> SiemAdapter -> OCSF -> correlation plus ATT&CK -> Glimmer triage -> pseudonymizer -> Spark reasoning -> Sigma rule -> backtest -> Wazuh shadow -> human approval
```

## Why Meta models

- Muse Glimmer has open weights under Apache 2.0, so high-volume triage runs on hardware the customer owns. We run it on an NVIDIA DGX Spark.
- Glimmer is distilled from Muse Spark, so on-prem triage and cloud reasoning stay consistent.
- Muse Spark reasons only over pseudonymized incidents, in English or Spanish.
- Muse Code is the coding agent used to build this repo.

## How we measure it

Ground truth comes from public attack datasets (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES) and Atomic Red Team chains in our own lab. Datasets are fetched reproducibly at pinned revisions with SHA-256 checksums (`scripts/fetch_datasets.py`, see `datasets/README.md`) into git-ignored `data/`; `eval/ground_truth.py` derives per-file ATT&CK labels into `data/ground_truth.json` (technique-level from OTRF metadata, tactic-level from EVTX folders). Alongside the atomic samples, one multi-stage chain (OTRF's APT29 day-1 compound file, day 2 not fetched) is evaluated at chain level only: its ground truth is the ordered 10-step chain in `eval/apt29_day1_ground_truth.json`, with per-step windows, anchors, and technique ids taken from the pinned MITRE emulation plan and resolved to current ATT&CK v20.0 ids (more-specific choices recorded as `refinements`, deprecated plan ids as dropped), because that dataset has no per-event labels and event-level precision cannot be computed on it. Step verdicts and counts reproduce with `eval/apt29_census.py` and are published in `eval/reports/apt29_day1_replay_load.md`. Metrics are attack chains detected, alert-to-incident reduction, false positives (the primary gate), rule precision, injection robustness, cost, and latency. Every published number carries its n, window, and producing script.

Results: TBD - published here as they are measured.

## Status

Work in progress, built during the Meta Global AI Developer Hackathon.

Run the skeleton stack:

- Copy `.env.example` to a file outside the repository (e.g.
  `/run/corvus/corvus.env`) and fill in secrets. Compose refuses to
  start when `CORVUS_ENV_FILE` is unset; services read every value
  from that file.
- `CORVUS_ENV_FILE=/run/corvus/corvus.env docker compose up --build -d`
  (Postgres 18: the image stores data at `/var/lib/postgresql/18/docker`
  and the Compose volume mounts `/var/lib/postgresql`. A volume created by
  Postgres 16 cannot be reused by 18: recreate the development volume
  with `docker compose down -v` before the first 18 start. Pre-release,
  there is no data to migrate.)
- Apply database migrations with `corvus db migrate` (reads
  `DATABASE_URL`; idempotent plain SQL in `corvus/state/migrations/`,
  safe to re-run, concurrent runners are serialized).
- Health (database plus model reachability): `curl http://127.0.0.1:8000/health`
  reports `degraded` when the database or the on-prem Glimmer model is
  unreachable; Muse Spark reachability is informational only.
- Settings come from the process environment only (`GLIMMER_BASE_URL`
  is required); no `.env` file inside the repository is ever read.
- From the dev machine Postgres is at `127.0.0.1:55432`; the test
  recipe is under `AGENTS.md` Commands. The skeleton was verified
  with `make lint` and the full `make test`, including the live
  migration test.

## Built during the hackathon

All product code in this repo was written between Oct 27 and Nov 4, 2026. The commit history shows what was built when.

## Data policy

This repo uses only public datasets or lab-generated data. It contains no customer data.

## License

AGPL-3.0 (see [LICENSE](LICENSE)). Maintained by Ekos Cyber Labs.
Third-party components keep their own licenses: `httpx2` is BSD-3-Clause (see https://github.com/pydantic/httpx2).
