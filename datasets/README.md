# Evaluation datasets

Public Windows atomic datasets used by the eval harness. Dataset files
are never committed (AGENTS.md rule 2): they live under `data/` (git
ignored) and are fetched with [fetch_datasets.py](../scripts/fetch_datasets.py).
Ground truth (per-file ATT&CK techniques and tactics) is derived with
[ground_truth.py](../eval/ground_truth.py) and written to
`data/ground_truth.json` (also git ignored): each key is a data-relative
path to an object with `dataset`, `techniques`, `tactics`, and
`label_source` (`otrf-metadata` | `otrf-folder` | `evtx-folder` |
`evtx-filename`; files no metadata links carry `otrf-folder`, tactic
only).

Fetch (from the repo root):

```bash
python3 scripts/fetch_datasets.py
python3 scripts/fetch_datasets.py --update-checksums  # first run only
python3 eval/ground_truth.py --out data/ground_truth.json
```

`fetch_datasets.py` downloads the pinned revisions below into `data/`,
skips files that already verify (idempotent), and checks every file's
SHA-256 against `checksums.txt`. Run with `--update-checksums` once
after the first download, inspect the diff, and commit the updated
`checksums.txt` so later runs verify instead of trusting the network.
`GITHUB_TOKEN` is optional (higher API rate limits); it is read from
the environment, never stored.

## 1. EVTX-ATTACK-SAMPLES

- Source: <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>
- Pinned revision: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
  (`master` as of 2023-01-24, `git ls-remote` HEAD on 2026-10-28).
- License: read from upstream `LICENSE.GPL` (GPL text without an
  `-only`/`-or-later` statement); GitHub reports `GPL-3.0`.
  SPDX id: `GPL-3.0`. Evaluation-only use with no redistribution of
  the data is permitted: we download the samples at eval time into
  git-ignored `data/` and never commit or re-host them.
- What we use it for: 279 Windows samples (278 `.evtx`, 1 `.etl`) of
  atomic attack and post-exploitation activity, replayed through the
  `ReplayAdapter` to measure detection / correlation / ATT&CK-mapping
  quality on Windows telemetry. Sample files only: the fetch keeps
  `.evtx`/`.etl` files under the top-level tactic folders (plus loose
  top-level samples) and drops `.pcap`/`.log`/`.md`/`.txt` and helper
  scripts.
- Ground truth: tactic-level only. Each sample's tactic comes from its
  top-level folder name mapped to the ATT&CK tactic name
  (`AutomatedTestingTools` and `Other` map to no tactic). At the pinned
  revision only 3 of the 279 file names carry a technique token
  (`evtx_data.csv` and `EVTX_ATT&CK_Metadata` give the tactic only),
  so filename technique tokens (`T####` with optional `.###`
  sub-technique, matched only when not glued to letters or digits) are
  kept when present and every other file maps to an empty technique
  list (unknown, never guessed). In `ground_truth.json` these files
  carry `label_source` `evtx-filename` when a token is present,
  otherwise `evtx-folder` (262 of 279 files carry a tactic).

## 2. OTRF Security-Datasets (atomic, Windows only)

- Source: <https://github.com/OTRF/Security-Datasets>
- Pinned revision: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`
  (`master` as of 2023-09-20, `git ls-remote` HEAD on 2026-10-28).
- License: read from upstream `LICENSE` (MIT text,
  "Copyright (c) 2021 Open Threat Research Forge"). SPDX id: `MIT`.
  Note: the upstream `README.md` still carries a stale
  "License: GPL-3.0" line pointing at the pre-move
  `Cyb3rWard0g/Security-Datasets` URL, but the repo's own `LICENSE`
  file, its MIT badge, and the GitHub license API all say MIT; the
  `LICENSE` file governs. Evaluation-only use with no redistribution
  is permitted under either text; we never commit or re-host the data.
- What we use it for: atomic Windows datasets under
  `datasets/atomic/windows/` (`host` and `network` zips) for
  technique-level detection eval, plus the small text metadata
  directory `datasets/atomic/_metadata/`. Other compound datasets
  and non-Windows platforms are out of scope and are not fetched;
  the one compound exception is section 3.
- Ground truth: technique-level from OTRF metadata. Each
  `datasets/atomic/_metadata/SDWIN-*.yaml` carries `attack_mappings`
  (`technique: Txxxx` plus optional `sub-technique: "yyy"`, combined
  to `Txxxx` or `Txxxx.yyy`) and a `files` list whose `link` URLs
  point at the dataset archives. `ground_truth.py` maps each fetched
  file under `datasets/atomic/windows/` (165 files, mostly `host` and
  `network` zips plus a few `.tar.gz`, capture, and JSON files) to
  the union of techniques from every metadata file linking to it (144
  of 165 carry at least one technique; the rest map to an empty list,
  unknown, never guessed), and to the tactic from its folder name (162
  of 165). In `ground_truth.json` linked files carry `label_source`
  `otrf-metadata`; files no metadata file links carry `otrf-folder`
  (tactic only).

## 3. OTRF Security-Datasets (compound, APT29 day 1 only)

- Source: <https://github.com/OTRF/Security-Datasets>, file
  `datasets/compound/apt29/day1/apt29_evals_day1_manual.zip` (OTRF's
  replay of the MITRE ATT&CK Evaluations APT29 round, day 1).
- Pinned revision: same OTRF pin as section 2,
  `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`. The `apt29/day1`
  folder is unchanged upstream since commit
  `be0e82209deae630529fa2fa289dacf360b52351`, so any OTRF pin at or
  after that gives identical bytes. Day 2 is not fetched, and neither
  are the day-1 pcaps or Zeek logs: the fetch prefix is the exact zip
  path.
- SHA-256: `98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5`
  (13,944,973 bytes zipped; one JSON-lines member of 385,334,029
  bytes, 196,081 records). Verified on every fetch; re-running the
  fetch downloads nothing.
- License: read from upstream `LICENSE` (MIT text,
  "Copyright (c) 2021 Open Threat Research Forge"). SPDX id: `MIT`.
  Evaluation-only use with no redistribution; we never commit or
  re-host the data.
- What we use it for: one multi-stage Windows attack chain (not
  atomic samples), replayed through the `ReplayAdapter` to measure
  chain-level visibility. The loader streams the member record by
  record; the whole file is never held in memory.
- Record layout (re-confirmed by a streaming field-name probe of the
  pinned file before loading, 2026-10-28): the same flat NXLog layout
  as the other OTRF JSON — fields at the root (`Channel`, `EventID`
  as a string, `RecordNumber`, `Hostname`, `@timestamp`, payload
  fields beside them), not nested under `winlog.event_data`. Times
  span 2020-05-02T02:55:26Z to 2020-05-02T03:28:20Z (`@timestamp`
  min/max, n = 196,081).
- Channels: a lowercase `security` channel (WEF-forwarded) alongside
  `Security`. The normalizer matches channels case-insensitively and
  keeps the canonical `Security` in `metadata.log_name`, so both
  spellings land in one `(channel, event id)` bucket and are not
  split or double-counted as separate channels (a probe by host,
  event id, record number, timestamp and message found no exact
  duplicate records across the two spellings; they are distinct
  forwarded records, counted once each). Both PowerShell channels
  occur: `Microsoft-Windows-PowerShell/Operational` 4103/4104 and
  `Windows PowerShell` 600/800 (4103, 4104 and 800 map to Script
  Activity; 600 is provider lifecycle and stays counted-unmapped).
- Ground truth: chain-level, not per event. The dataset carries no
  per-event labels, so **event-level precision cannot be computed
  on this dataset** — there is no labelled set of attack events to
  be precise over. Ground truth is the ordered 10-step chain in
  `eval/apt29_day1_ground_truth.json` (committed), built from the
  public MITRE emulation plan: `mitre-attack/attack-arsenal`,
  `adversary_emulation/APT29/Emulation_Plan/Day 1`, pinned at
  `8b290be3b53fcccd477eb79f2bcedbbc158c966c`, Apache-2.0 (read from
  upstream `LICENSE.txt`). Each step carries its own time window,
  lowercase anchors, the plan's technique ids (`plan_techniques`),
  current ids resolved against ATT&CK v20.0 revoked-by relationships
  (`techniques`; for example plan T1122 resolves to T1546.015, not
  Modify Registry, and plan T1081 to T1552.001), any more-specific
  choice recorded in `refinements` with its reason (for example
  T1555.003 kept only as a refinement of T1552.001 for the Chrome
  theft in step 6), any deprecated plan id with no replacement
  recorded as dropped (plan T1043), and the event types that count
  as technique-relevant evidence. Step verdicts (direct, indirect,
  or none) are computed by `eval/apt29_census.py`, which re-derives
  each window from anchor hits and reports the difference against
  the committed window; the chain window above is taken from the
  data. In
  `data/ground_truth.json` this file carries `label_source`
  `otrf-compound-chain` with empty per-file techniques, so no
  per-event label is ever invented. Dataset name, file name,
  technique ids, anchors and windows live only in that
  ground-truth file, the eval code, and replay provenance, never
  in OCSF records or anything a model can see (enforced by
  `tests/test_chain_ground_truth.py`).
- Known visibility gaps (expected in the unmapped counts, not
  normalizer bugs): the step-5 service install (T1543.003) surfaces
  as Security 4697 / System 7045 and Sysmon 13 service-key writes,
  not mapped yet. The pinned OCSF 1.9.0 win extension defines
  Windows Service Activity (`windows_service_activity`, attribute
  `win_service`), Registry Key Activity and Registry Value Activity
  (`registry_key_activity` / `registry_value_activity`) for these
  records; those classes exist in the pinned schema and are not
  mapped yet (the next mapping step), and mapping service installs
  to Scheduled Job Activity would mislabel them in the meantime.
  Registry modification (steps 3 and 5, T1112 / T1547.001) surfaces
  as Sysmon 12/13/14, likewise not mapped yet. Step 10 is not a
  gap: after the reboot, a mapped Sysmon 1 process creation of the
  service binary by the service controller, with a mapped rundll32
  child seconds later, is direct Process Activity evidence of the
  service executing. Each step has its own window and anchors in
  the chain file, so the shared step-5/step-10 artifact is counted
  in one step per hit, never both.

## Checksums

`checksums.txt` holds `SHA-256  data-relative-path` lines for every
fetched file at the pinned revisions (549 lines). It is populated via
`--update-checksums` and committed; the maintainer reviews the diff
on re-pins. Later runs fail closed on any mismatch or any unlisted
file.
