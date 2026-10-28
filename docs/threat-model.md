# Corvus threat model

Attackers control parts of log content that flow into prompts: usernames,
command lines, URLs, user agents, file and task names. All controls below
live in `corvus/guardrails`, which wraps every model call. Every guardrail
block is logged and counted by the evaluation harness (injection robustness
metric).

| Risk | Control |
|---|---|
| Prompt injection causing a benign verdict | Deterministic score floor (asymmetry): the model may never lower severity below the floor; a database CHECK keeps `severity_id` at or above `severity_floor` (human override path comes later). |
| Prompt injection inflating severity to burn cloud budget / cause alert fatigue | Model may raise severity by at most one level, only citing validated evidence event ids; the same database CHECK caps `severity_id` at the floor plus one; per-incident and daily USD spend caps. |
| Secrets inside log content (tokens, passwords in command lines) reaching the cloud | Secret-pattern redactor in the egress filter. |
| Data leaking to the cloud | Egress filter before every Spark call: no known entity value (IPs, hosts, users, domains, user paths, SIDs) may appear in the payload, including inside free text; on failure the call is not sent. |
| Instructions inside data | Data sent as escaped, delimited JSON marked untrusted; fields truncated; chat-template special tokens stripped. |
| Injection attempts | Deterministic pattern detector (plus an optional classifier, roadmap, to be evaluated); a detected attempt becomes a signal of the incident itself. Security-validator failures are NOT retried: quarantined, logged as security events. |
| Generated rules carrying attacker-controlled strings into SIEM config | Every value XML-escaped; `wazuh-logtest` plus configuration validation before any write; previous rule file restored if the manager fails to restart. |
| Rule poisoning | Additive-only learning; scope limits; backtest with zero false positives on the benign baseline; human approval for SIEM deployment. |
| Tool abuse by the agent | Read-only tools, typed parameters, no network access, row and step limits. |
| Unauthenticated model endpoint (vLLM has no auth) | Bound to localhost or a private overlay network interface only, never `0.0.0.0`. |
| Network exfiltration beyond the filter | Content filtering is not network control: network-level egress is the operator's firewall; the HTTP client only talks to an allowlist of hosts (model endpoints, Wazuh). |
| Ground-truth leakage in evaluation | Dataset names, source file names, ground-truth technique ids, anchors and step windows never reach a model; a harness test enforces it. |
| XSS from logs or model output in the UI | Render as text only; strict Content-Security-Policy. |
| Cost / DoS | Per-cluster size limits, per-incident token budget, bounded queue, USD spend cap with degraded mode. |

Out of scope for this document: operator host hardening and firewall rules
(the deployer's responsibility); vLLM and Postgres CVEs (tracked by image
updates).
