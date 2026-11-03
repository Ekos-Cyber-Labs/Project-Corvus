# Corvus demo script (about 3 minutes)

Prerequisite: a running stack with data (README "Run it yourself",
parts 6 or 7). Open `http://127.0.0.1:8000/` in a browser.
Everything on screen is read-only; every command below ran on the
host, never from the console.

## 1. Dashboard (35 seconds)

Screen: Dashboard, route `#/` (also `#/dashboard`). In the sidebar,
point at the count pill on Incidents and the sweep box
("Sweep running", "Sweep paused", or "Sweep not detected", with
"Next in m:ss" counting down to the next run).

Say: four stat cards — Open incidents, Analyzed with a verdict,
Injection quarantined ("Model never obeyed"), and Model spend
against its cap. «Incidents by final severity» shows Critical,
High, Medium, and Low bars with the verdict split under the bars
(true positive, benign, needs human, quarantined, failed, pending).
«Alert activity» is 24 hourly bars with sweep runs as dashed
markers. «Latest verdicts from the sweep» lists the recent resolved
analyses, and «Sweep status» closes with the policy sentence:
which floor, up to how many analyses per sweep, and the spend cap.

Command that produced the sweep data: `corvus sweep` on the host
(README part 8).

## 2. Incidents and one explained chain (60 seconds)

Screen: Incidents, route `#/incidents`. The quick-filter chips are
All, Analyzed, Pending, and Quarantined, beside search ("Search
title, host or technique"), "Floor at least", "Severity", and the
"Analyzed" select.

Say: Wazuh produced the alerts; Corvus correlated them into this
short list. Select a row and use the preview panel on the right —
severity gauge with its "Floor kept" or "Floor raised one level by
the model" caption, the kill-chain chips, and a two-line summary —
then «Open full analysis» (`#/incidents/<id>`). Top to bottom: the
deterministic severity floor with its factors (the model can raise
it at most one level, never lower it silently), the ATT&CK
techniques, the Timeline where every claim cites an event id, the
evidence behind those ids, and the agent trace with each bounded
tool call and its token cost. The verdict and response plan follow,
in English or Spanish.

Commands that produced it: `corvus correlate replay` (or a Wazuh
poll, `corvus wazuh poll --once`), then `corvus analyze --incident <id>`.

## 3. What the cloud model saw, and the injection example (35 seconds)

Screen: the same incident, `#/incidents/<id>`, pseudonym view.

Say: raw values never left the network. The reasoning model saw
pseudonyms such as `HOST-0003`; this screen maps them back locally.
Open a quarantined incident next (the Quarantined chip): attacker
text tried to steer the model, the deterministic detector recorded
it as a signal, and the answer was quarantined, never retried into a
verdict. The Model attempts panel records every attempt, its
outcome, and its cost.

## 4. Rules in shadow, with lineage (40 seconds)

Screen: Rules, route `#/rules`: the lifecycle summary bar on top
(Proposed, Backtested, Shadow, Active, each with its count), the
rule list on the left, and the detail on the right (`#/rules/<id>`
opens the same detail full-page).

Say: in shadow, the banner states the guarantee — "Shadow mode.
This rule is evaluated and logged only. It never changes an alert
until a human promotes it." «Backtest» gives the big numbers with
their n; «Sigma rule (text only)» has the Copy button; «Lineage»
ties the rule to its Source incident, Cited event uids, Accepted
backtest, Rounds used, Model, and Prompt version; and «Lifecycle
history» is the timeline naming the approver and reason for each
move.

Commands that produced it: `corvus rules propose --incident <id>`,
`corvus rules backtest`, `corvus rules approve <id> --to shadow
--approver NAME --reason TEXT`, then the manual Wazuh round trip in
`docs/wazuh.md`, section 10.

## 5. Settings (10 seconds)

Screen: Settings, route `#/settings`.

Say: policy and connections, read-only. The page shows the effective
sweep policy and each endpoint as connected, unreachable, or not
configured — addresses only, secrets never shown, and nothing here
can be edited. To change anything, edit the env file on the host and
restart.

Close: Corvus turns Wazuh alerts into a few explained chains, learns
rules that stay in shadow until a human approves them, and keeps raw
logs on-prem throughout.
