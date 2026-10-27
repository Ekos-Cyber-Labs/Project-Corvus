# Project Corvus

An on-prem AI SOC analyst that turns thousands of security alerts into a few explained attack chains, without logs leaving your network.

## The problem

Small companies run Linux servers and Windows endpoints, often with Wazuh as their only security tool and no 24/7 SOC. Existing AI SOC tools are enterprise-priced SaaS that require shipping raw logs to a vendor cloud. Real attacks stay buried in uncorrelated alerts.

## How it works (planned)

- Ingest Wazuh alerts and archives, Windows EVTX and Sysmon, and Linux auth.log, journald, and auditd.
- Normalize sources into OCSF events and keep them in a local store.
- Correlate deterministically by host, user, IP, process, and time window, and map to MITRE ATT&CK to form candidate incidents.
- Triage candidate incidents on-prem with Muse Glimmer through an async batch queue.
- Pseudonymize incidents before any external reasoning call.
- Reason with Muse Spark for verdict, timeline, response in English or Spanish, and tool calls into the store.
- Propose Sigma and Wazuh XML rules, backtest them against the data, and wait for human approval.
- Review incidents in a web UI (planned) and check changes with an eval harness (planned).

```
sources -> normalizers -> OCSF store -> correlation plus ATT&CK -> Glimmer triage -> pseudonymizer -> Spark reasoning -> proposed rules plus human approval
```

## Why Meta models

- Muse Glimmer has open weights under Apache 2.0, so high-volume triage runs on hardware the customer owns. We run it on an NVIDIA DGX Spark.
- Glimmer is distilled from Muse Spark, so on-prem triage and cloud reasoning stay consistent.
- Muse Spark reasons only over pseudonymized incidents, in English or Spanish.
- Muse Code is the coding agent used to build this repo.

## How we measure it

Ground truth comes from public attack datasets (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES, AIT Log Data Set) and attack chains replayed live with Atomic Red Team in our own lab. Metrics are attack chains detected, alert-to-incident reduction, false positives, and rules that catch what was missed without new false positives.

Results: TBD - published here as they are measured.

## Status

Work in progress, built during the Meta Global AI Developer Hackathon.

## Built during the hackathon

All product code in this repo was written between Oct 27 and Nov 4, 2026. The commit history shows what was built when.

## Data policy

This repo uses only public datasets or lab-generated data. It contains no customer data.

## License

AGPL-3.0 (see [LICENSE](LICENSE)). Maintained by Ekos Cyber Labs.
