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
  directory `datasets/atomic/_metadata/`. Compound datasets and
  non-Windows platforms are out of scope and are not fetched.
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

## Checksums

`checksums.txt` holds `SHA-256  data-relative-path` lines for every
fetched file at the pinned revisions (548 lines). It is populated via
`--update-checksums` and committed; the maintainer reviews the diff
on re-pins. Later runs fail closed on any mismatch or any unlisted
file.
