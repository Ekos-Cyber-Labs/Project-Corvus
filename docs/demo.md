# Corvus demo script (about 3 minutes)

Prerequisite: a running stack with replayed data (see README Quickstart).
Open `http://127.0.0.1:8000/` in a browser.

## 1. The incident list (30 seconds)

Screen: the incident table (`#/`, columns ID, Title, Floor, Final, Verdict,
Events, Injection).

Say: Wazuh produced thousands of alerts; Corvus correlated them into this
short list. Floor is the deterministic severity floor, Final is the
model-adjusted severity (at most one level above the floor). The Injection
badge marks incidents where attacker-controlled text tried to steer the
model.

## 2. One explained chain (60 seconds)

Screen: click the top incident (`#/incidents/<id>`).

Walk, top to bottom: the severity floor with its factors; the ATT&CK
technique list; the Timeline, where every claim cites an event id; the
evidence entries behind those ids; the agent trace showing each bounded
tool call with its token cost. Point out the verdict and the response
plan in English or Spanish.

Command that produced it: `corvus analyze` (Spark reasoning over the
pseudonymized incident) after `corvus correlate replay`.

## 3. What the cloud model sees (30 seconds)

Screen: the same incident detail, pseudonym note and reasoning panel.

Say: raw values never leave the network. The model saw pseudonyms such as
`HOST-0003` instead of hostnames; this screen maps them back locally
(`pseudonym_resolution`, resolved locally). The Model attempts and cost panel
(`llm_attempts`) on this screen records every model attempt with its outcome
and token source.

## 4. The learned rule in shadow mode (60 seconds)

Screen: the rules list (`#/rules`), then one rule (`#/rules/<id>`).

Walk: the Sigma text; the Lineage panel (source incident, cited event uids,
accepted backtest, rounds used, model, prompt version); the transitions
table with the human approver and reason; the Shadow mode banner stating
that shadow rules never change alerts.

Commands that produced it: `corvus rules propose --incident <id>`,
`corvus rules backtest`, `corvus rules approve <id> --to shadow
--approver NAME --reason TEXT`, `corvus rules export-wazuh <id> --out DIR`,
`corvus rules logtest <id> --bundle DIR`.
