# Connect Corvus to your Wazuh

Corvus reads Wazuh. It never writes to the indexer, never calls the
Wazuh manager API, and never deploys anything by itself. This page
takes you from a running Corvus stack (see the README "Run it
yourself" guide) to a first read-only poll against your own Wazuh
4.x indexer, and back again with a learned rule.

Everything below was checked against `corvus/adapters/wazuh/` and
`corvus/live/`. Steps that need a real Wazuh indexer, its admin
account, or a manager host are marked **not verified here**; they
were not run against a live Wazuh in this environment.

## 1. What Corvus reads, and why archives are optional

| Index pattern | When it is read | Why |
|---|---|---|
| `wazuh-alerts-4.x-*` | Every poll (`corvus wazuh poll`, and every sweep cycle) | Wazuh rule matches. Each alert becomes an OCSF Detection Finding (2004) plus its mapped event. This is the only input correlation needs. |
| `wazuh-archives-4.x-*` | Only with `--with-archives` | All ingested log events, not just rule matches. Corvus fetches surrounding archive context for each *new* incident (entity and time window, at most `--archives-limit` events, default 200). Useful evidence, never required. |

The constants live in `corvus/adapters/wazuh/adapter.py`
(`ALERTS_INDEX`, `ARCHIVES_INDEX`). The read-only client
(`corvus/adapters/wazuh/client.py`) refuses any other index pattern
before a request is sent, accepts only `https` URLs, and only sends
search and point-in-time requests. There is no write path to audit:
if a future change added one, the client allowlist would reject it.

Skip archives on your first run. Add `--with-archives` later, once
alerts poll cleanly and you know the archive volume (next section).

### Enable archive indexing in Wazuh (optional, manager side)

**Not verified here: needs a Wazuh manager you administer.**

Archives exist only when the manager archives every event and
Filebeat ships them. On the Wazuh manager:

1. In `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`, enable
   JSON archiving:

   ```xml
   <logall_json>yes</logall_json>
   ```

   Plain `<logall>yes</logall>` archives in plain format; Corvus
   reads the indexer, so the JSON form plus the Filebeat archives
   module below is the combination that fills
   `wazuh-archives-4.x-*`.

2. In the manager Filebeat configuration (`/etc/filebeat/filebeat.yml`
   on a standard install), enable the archives module alongside
   alerts:

   ```yaml
   filebeat.modules:
     - module: wazuh
       alerts:
         enabled: true
       archives:
         enabled: true
   ```

3. Restart both services, in this order:

   ```bash
   systemctl restart wazuh-manager
   systemctl restart filebeat
   ```

Caveat: archiving stores *every* event, not only alerts. On a busy
manager this grows disk much faster than alerts alone. Enable it
only with retention and disk headroom planned, and watch the
`wazuh-archives-4.x-*` indices after turning it on.

## 2. Create a dedicated read-only indexer user

**Not verified here: needs indexer admin access, once, by you.**
Never point Corvus at the indexer `admin` account. Create a role
that can only read the two index patterns, a user for Corvus, and a
mapping between them. The names below (`corvus_ro`, `corvus-reader`)
are examples; pick your own and use them consistently.

Option A: OpenSearch Dashboards (Wazuh dashboard) — Security,
Roles, Create role; then Security, Internal users, Create internal
user; then map the user in the role's Mapped users tab.

Option B: the indexer security API, run once by an administrator.
Replace the example password before running anything; do not reuse
this example value.

```bash
# Role: read-only search on the two Corvus index patterns.
curl -k -u admin:<admin-password> -X PUT \
  https://<indexer-host>:9200/_plugins/_security/api/roles/corvus_ro \
  -H 'Content-Type: application/json' -d '{
  "cluster_permissions": [],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
    "allowed_actions": [
      "indices:data/read/search*",
      "indices:data/read/point_in_time*"
    ]
  }],
  "tenant_permissions": []
}'

# User: Corvus only.
curl -k -u admin:<admin-password> -X PUT \
  https://<indexer-host>:9200/_plugins/_security/api/internalusers/corvus-reader \
  -H 'Content-Type: application/json' -d '{
  "password": "<choose-a-new-password>",
  "backend_roles": [],
  "attributes": {}
}'

# Mapping: put the user in the role.
curl -k -u admin:<admin-password> -X PUT \
  https://<indexer-host>:9200/_plugins/_security/api/rolesmapping/corvus_ro \
  -H 'Content-Type: application/json' -d '{
  "backend_roles": [],
  "hosts": [],
  "users": ["corvus-reader"]
}'
```

Notes on the exact scope:

- `indices:data/read/search*` covers the `_search` reads.
  `indices:data/read/point_in_time*` covers the point-in-time open,
  search, and close the adapter uses to page without skipping rows
  (`corvus/adapters/wazuh/client.py`). If your indexer build splits
  point-in-time into create/search/delete actions, grant all three
  read-side actions; Corvus sends nothing else.
- `-k` above is for the one-off admin calls only, from the admin's
  own workstation. Corvus itself never disables verification
  (next section).
- After this step, the admin credentials go away. Corvus only ever
  holds `corvus-reader` (or your equivalent).

## 3. Get the CA certificate

A stock Wazuh indexer serves HTTPS with a self-signed certificate
signed by the Wazuh root CA, so your platform trust store cannot
verify it. Copy the root CA once, from the indexer host:

```bash
# On the indexer host (standard Wazuh 4.x path):
#   /etc/wazuh-indexer/certs/root-ca.pem
# From your Corvus host:
scp <indexer-host>:/etc/wazuh-indexer/certs/root-ca.pem /run/corvus/wazuh-indexer-ca.pem
chmod 644 /run/corvus/wazuh-indexer-ca.pem
```

**Not verified here: needs your indexer host and its file layout.**
If your indexer uses a certificate from your own PKI instead, use
that CA bundle; the mechanism is identical.

Set `WAZUH_INDEXER_CA` to the copied file in your Corvus env file
(outside the repository). Two hard properties, from the code:

- TLS verification is always on. There is no flag, environment
  variable, or config option to disable it
  (`corvus/adapters/wazuh/client.py` builds a verifying
  `ssl.SSLContext`; only the strict Key Usage check is relaxed,
  because a stock Wazuh root CA carries no Key Usage extension —
  chain and hostname checks stay on).
- Only `https` indexer URLs are accepted. An `http` URL raises
  before any request is sent.

The certificate's hostname must match the host in
`WAZUH_INDEXER_URL`. Through an SSH tunnel (next section) that
usually means the indexer node name, not `127.0.0.1`.

## 4. Reach the indexer: same network or SSH tunnel

Corvus needs one HTTPS endpoint: the indexer, port 9200 by default.

Same network (indexer reachable directly):

```bash
WAZUH_INDEXER_URL=https://<indexer-host>:9200
```

SSH tunnel (indexer not directly reachable). Run this on the Corvus
host and leave it running; it binds the indexer to localhost only:

```bash
ssh -N -L 9200:<indexer-host>:9200 <user>@<bastion-or-indexer-host>
```

Then point Corvus at the indexer name *as the certificate sees it*.
If the certificate names the indexer host, add a hosts entry so the
name resolves to the tunnel, instead of weakening verification:

```bash
# /etc/hosts on the Corvus host:
127.0.0.1 <indexer-host>
```

```bash
WAZUH_INDEXER_URL=https://<indexer-host>:9200
```

**Not verified here: needs your network and tunnel host.** A closed
tunnel shows up as connection refused; see Troubleshooting below.

## 5. Environment variables

Put these in the env file outside the repository (see the README
guide, part 3). Restart Corvus after changing them.

| Variable | Required | Meaning |
|---|---|---|
| `WAZUH_INDEXER_URL` | Yes, for any poll or sweep | Indexer base URL. Must be `https`. |
| `WAZUH_INDEXER_USER` | Yes | The read-only user from section 2. Never the admin account. |
| `WAZUH_INDEXER_PASSWORD` | Yes | That user's password. Secret; never logged by the client. |
| `WAZUH_INDEXER_CA` | With self-signed certs | Path to the CA bundle from section 3. When unset, the platform trust store is used. A set path that does not exist fails fast with `FileNotFoundError`. |
| `CORVUS_OPERATOR_SOURCES` | No | Networks you administer the monitored hosts from (comma or space separated CIDRs or addresses, at most /16 for IPv4 and /48 for IPv6). Your own SSH sessions from them (login, PAM, sudo) are marked as operator sessions: kept as Informational audit incidents, never joined to attack incidents, never analyzed automatically. Activity mapping to any technique other than T1078, T1021 or T1548, or carrying an injection signal, is never marked. A malformed entry stops the poll with the entry's position. Unset: no marking. Setting or changing it re-splits stored incidents: a stored incident that loses members returns to pending with its analysis removed, and the split-off part is a new pending incident. |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` | No | Declared in `corvus/settings.py` but **not read by any current code path** (checked across `corvus/`). They reserve names for a possible future manager-API integration. Leave them blank; Corvus does not need the Wazuh manager API. |

Poll and sweep also need `DATABASE_URL` and `GLIMMER_BASE_URL` to be
set in the environment (the settings loader requires them even
though a poll calls no model).

## 6. First read-only check (no Corvus, no stored secret printed)

Prove the read-only user works before involving Corvus. This prompts
for the password instead of putting it on the command line:

```bash
curl --cacert /run/corvus/wazuh-indexer-ca.pem \
  -u corvus-reader \
  'https://<indexer-host>:9200/wazuh-alerts-4.x-*/_count'
```

Expected: HTTP 200 with a JSON `count`. **Not verified here: needs
your indexer and read-only user.** A `401` means the user or password
is wrong; a `403` means the role or mapping is missing (section 2);
a certificate error means the CA file or hostname is wrong
(section 3).

## 7. First poll: `corvus wazuh poll`

Polling calls no model. One cycle streams new alerts, writes them to
a local store, correlates deterministically, and upserts incidents
in Postgres.

```bash
corvus wazuh poll --once --since 2026-11-01T00:00:00Z --max-docs 500 --store data/live
```

Add `--with-archives` only after section 1 is enabled and you want
archive context for new incidents:

```bash
corvus wazuh poll --once --since 2026-11-01T00:00:00Z --max-docs 500 --with-archives --store data/live
```

Every flag (from `corvus wazuh poll -h`, verified here):

| Flag | Meaning |
|---|---|
| `--once` | Run a single cycle and stop. This is the default when `--interval` is absent. |
| `--interval SECONDS` | Loop every SECONDS until SIGINT, instead of running once. |
| `--store DIR` | Live replay-format store directory (default `data/live`). Parquet events, findings, and provenance land here. |
| `--since ISO-8601` | Seed cursor only when no checkpoint is stored. A stored checkpoint always wins, so restarts resume. |
| `--with-archives` | Fetch surrounding archive events for each new incident. |
| `--archives-limit N` | Archive events per incident, at most (default 200, allowed 1 to 200). |
| `--page-size N` | Alerts per indexer page, at most 1000 (default 500). |
| `--max-docs N` | Documents per cycle, at most (default 5000). Start small (500) on a first run. |
| `--database-url URL` | Postgres URL (default: `$DATABASE_URL`). |
| `--attack PATH` | Compact ATT&CK dictionary (default `data/attack/enterprise.json`). Required: `corvus wazuh poll` fails with `FileNotFoundError` without it. Build it once with `python3 scripts/fetch_datasets.py --only mitre-cti` and `uv run corvus attack build` (about 49 MB; see the README, part 7). |

How resuming works: the adapter pages with `search_after` on
`[timestamp, _id]` inside a fresh point in time, re-reads a 120-second
overlap window behind the cursor, and drops only already-seen uids,
so late-indexed alerts are emitted exactly once. The checkpoint
(adapter `wazuh`, stream `alerts`) is saved only after the store
write and the incident upsert both succeed, so a failed cycle
re-reads the same window and the idempotent store delivers every
alert exactly once. Alerts more than 10 minutes ahead of the poll
clock are counted as `future_dated` and never advance the checkpoint.
Late alerts older than the overlap window stay missed; that bound is
documented behavior, not a silent drop.

What is written where:

- Store directory (`--store`, default `data/live`): Parquet
  `events/`, `findings/`, and `provenance/` in replay format, plus a
  manifest. Safe to inspect; delete the directory only when you mean
  to re-read from `--since` (see Cleanup in the README).
- Postgres: `incidents` (correlated chains), `checkpoints` (resume
  cursor), and one `wazuh_poll_cycles` row per cycle with the counts,
  closed as `ok` or `failed` with the exception class. Learned-rule
  attribution, when a stored rule matches, is recorded on the cycle
  counts (`learned_findings`, `shadow_findings`).

Inspect the result:

```bash
curl http://127.0.0.1:8000/api/dashboard
```

Then open the console at `http://127.0.0.1:8000/` (Incidents,
`#/incidents`) and read the chains. There is deliberately no
`corvus incidents list` CLI; the console and the read-only API are
the inspection surface. Cycle counts without the console: query
`wazuh_poll_cycles` in Postgres, newest first.

## 8. Run the sweep against your Wazuh

Once a single poll works, the sweep repeats poll-then-analyze on an
interval (poll, select pending incidents by policy, triage on-prem,
then pseudonymized reasoning). One trial cycle first:

```bash
corvus sweep --once --store data/live
```

Then the loop (defaults: every 300 seconds, at most 5 analyses per
cycle, severity floor at least high, injection-signal incidents
always analyzed, spend capped by `SPEND_CAP_USD`):

```bash
corvus sweep --store data/live
```

**Not verified here: needs your Wazuh plus a reachable triage model;
analysis additionally needs the reasoning model under `hybrid`.**
The sweep reuses the same poll cycle, checkpoint, and store as
section 7 (`--replay-dir` defaults to `--store`). It never proposes,
deploys, or approves rules. Full policy and flags: README part 8 and
`corvus sweep -h`.

## 9. Troubleshooting (errors the code can actually raise)

| Symptom | What the code does | Fix |
|---|---|---|
| `certificate verify failed` (TLS error on poll, or `curl` in section 6) | Verification always runs; a self-signed chain or hostname mismatch fails closed. | Copy the right `root-ca.pem` (section 3), set `WAZUH_INDEXER_CA`, and use the certificate's hostname in `WAZUH_INDEXER_URL` (hosts entry through a tunnel, section 4). There is no disable switch to reach for. |
| `FileNotFoundError: wazuh indexer CA bundle not found` | `WAZUH_INDEXER_CA` is set but the file does not exist; the client fails before connecting. | Fix the path, or unset the variable to use the platform trust store (public-CA certificates only). |
| `wazuh indexer ... : HTTP 401` | Wrong user or password. The error names only the operation, index pattern, and status — never credentials. | Re-check `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` in the env file; confirm the internal user exists (section 2). |
| `wazuh indexer ... : HTTP 403` | Authenticated, but the role does not allow the action on that index pattern. | Grant the section 2 role (search plus point-in-time read actions on both patterns) and map the user into it. Archives need the same grant on `wazuh-archives-*`. |
| `wazuh indexer ... : HTTP 404` | The index pattern matched no index (for example archives requested before any archive document exists, or a Wazuh major version other than 4.x). | Confirm the indices exist in the indexer (`wazuh-alerts-4.x-*` first). Drop `--with-archives` until archives are enabled and populated. |
| Empty result, no error (`alerts_seen: 0`) | The time window or cursor is ahead of your data: `--since` only seeds an empty checkpoint, and a stored checkpoint always wins. | For a first proof, use a fresh `--store` and a database with no `wazuh`/`alerts` checkpoint, and set `--since` before your oldest alert. Otherwise wait for new alerts; the poll is incremental by design. |
| `transport error (ConnectError)` / connection refused | Nothing answered: wrong host or port, indexer down, or the SSH tunnel is closed. | Check `WAZUH_INDEXER_URL`, re-open the tunnel (section 4), and re-run the section 6 `curl` to separate network from Corvus. |
| `wazuh poll needs from the environment: ...` | A required variable is missing; the CLI refuses before connecting. | Set `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, and `WAZUH_INDEXER_PASSWORD` (plus `DATABASE_URL` and `GLIMMER_BASE_URL`) in the environment. |
| `wazuh indexer URL must use https` | An `http` URL was configured; refused before sending. | Use `https`, including through the tunnel. |

Retries: HTTP 429 and 5xx are retried a bounded number of times with
backoff and jitter; other 4xx and transport errors fail fast. A
failed poll cycle closes its `wazuh_poll_cycles` row as `failed`
with the exception class and re-raises; the checkpoint does not
advance, so the next cycle retries the same window.

## 10. The rule round trip back to Wazuh (manual, human-gated)

Learned rules return to Wazuh as an offline bundle. Corvus never
copies files onto your manager and never restarts it.

```bash
corvus rules export-wazuh <rule-id> --out <bundle-dir>
```

This writes (refusals write nothing):

- `wazuh_rule.xml` — the translated Wazuh rules. Shadow mode groups
  them under `corvus_shadow` (active exports use `corvus_active`);
  each stored rule gets two native rule ids in the learned range,
  one under the sudo parent chain and one under the auditd chain.
  Shadow levels sit so no existing alert is hidden or downgraded;
  promotion to active raises them (see the bundle's own plan for the
  exact levels of your rule).
- Raw logtest inputs with location and agent, `expected.json` (which
  lines must fire, from fresh Sigma matches), and `deploy_plan.txt`
  (the exact steps below for your rule).

The default stores are the replay lab stores. For a rule learned
from incidents read live from the indexer, pass the live store the
rule came from: `--chain-dir <live-store>` (and `--baseline-dir` for
the benign sample; the same store works, lines already bundled as
targets are not repeated). Live stores keep no archive file and
line, so each raw line comes from the event's stored `raw_data`;
a target whose `full_log`, `location`, `decoder` or `agent` was
truncated at ingest is refused.

Deploy is a human step, on the manager, following the bundle's
`deploy_plan.txt`:

1. Append the bundle's `<group name="corvus_<sigma-id>,">` block from
   `wazuh_rule.xml` to `/var/ossec/etc/rules/local_rules.xml` on the
   manager, keeping the XML well-formed.
2. Test the configuration: `wazuh-analysisd -t` must print no error.
   Fix the XML; never skip this step.
3. Restart the manager: `systemctl restart wazuh-manager`.
4. Prove parity before trusting it: run the bundle lines through
   `wazuh-logtest` and compare with Sigma. With the logtest bridge
   command configured (`CORVUS_WAZUH_LOGTEST_CMD`), that is
   `corvus rules logtest <rule-id> --bundle <bundle-dir>`.
5. Check the shadow behavior: matching alerts keep their count and
   level and now carry the `corvus_shadow` group.

**Not verified here: needs a Wazuh manager and `wazuh-logtest`.**
Rollback is equally manual and instant: remove the Corvus group
block, re-run `wazuh-analysisd -t`, restart the manager. Promoting a
rule from shadow to active inside Corvus
(`corvus rules approve <id> --to active ...`) changes what the next
export generates; it does not touch your manager either. Nothing in
this round trip happens without a named human approver and an
operator pasting the file.
