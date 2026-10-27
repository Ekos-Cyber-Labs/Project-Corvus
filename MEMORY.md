# MEMORY.md — Project Corvus durable notes

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
