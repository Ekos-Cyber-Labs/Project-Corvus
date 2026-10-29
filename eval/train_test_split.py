"""Deterministic train/test split of OTRF recordings per technique.

Exercised by the learning-curve harness (rules are evaluated on data they
did not learn from)::

    uv run python eval/train_test_split.py

The split unit is a *recording*, not a file: OTRF ships the same
recording twice, under ``.../host/<name>.zip`` and
``.../network/<name>.zip``. Splitting files would put both captures of
one attack on opposite sides (train on one, test on the other) and leak.
The recording key is the data-relative path with a ``host``/``network``
segment dropped; both siblings always land on the same side.

Rules, one per technique:

- Group OTRF technique-labelled files (``label_source == "otrf-metadata"``)
  by technique id; a recording carrying several technique ids is listed
  under each of them.
- Drop non-ATT&CK ids (anything that is not ``Tdddd[.ddd]``, plus the
  all-zero OTRF placeholder ``T0000``); they are reported under
  ``excluded``, never silently.
- Within one technique, rank that technique's *recordings* by the hex
  SHA-256 of the recording key and split the ranking: the first
  ``max(1, n // 2)`` recordings test, the rest train. The hash decides,
  so the split is deterministic and a recording is never in both sides
  of its technique.
- A technique with fewer than two recordings is marked ``untestable``
  (its files stay on the train side only, never duplicated into test);
  the harness must exclude untestable techniques from test metrics
  instead of measuring them on their own training data.
- Purge: a recording on the train side of *any* technique is removed
  from *every* test side (a rule trained on a recording must not be
  tested on that same recording through another technique's test side).
  A technique left with no test recordings becomes untestable.
  ``multi_label_files`` still discloses every file labelled with more
  than one technique.

Only ``eval/ground_truth.py`` label shapes are read (data-relative path to
``{"dataset", "techniques", "tactics", "label_source"}``); dataset paths
never enter model inputs through this module (it emits counts and path
lists for the harness only).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

OTRF_DATASET = "security-datasets"
OTRF_METADATA_SOURCE = "otrf-metadata"

TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?$")

#: OTRF placeholder ids: all-zero ids name no ATT&CK technique.
PLACEHOLDER_IDS = frozenset({"T0000", "T0000.000"})


def is_attack_id(technique: str) -> bool:
    """True for ids that can name an ATT&CK technique (never placeholders)."""
    return TECHNIQUE_ID.fullmatch(technique) is not None and (
        technique not in PLACEHOLDER_IDS
    )


def recording_key(path: str) -> str:
    """Collapse one recording's captures to a single split unit.

    Drops a path segment exactly equal to ``host`` or ``network``, so
    ``.../host/<name>.zip`` and ``.../network/<name>.zip`` share a key
    and always land on the same side.
    """
    return "/".join(
        segment for segment in path.split("/") if segment not in ("host", "network")
    )


def rank_key(unit: str) -> str:
    """Deterministic rank of one recording key (hex SHA-256)."""
    return hashlib.sha256(unit.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TechniqueSplit:
    """Train/test file lists for one technique id."""

    technique: str
    train: tuple[str, ...] = ()
    test: tuple[str, ...] = ()
    untestable: bool = False


@dataclass
class OtrfSplit:
    """Whole split: per-technique lists, multi-label disclosure, excluded."""

    techniques: dict[str, TechniqueSplit] = field(default_factory=dict)
    multi_label_files: dict[str, list[str]] = field(default_factory=dict)
    excluded: dict[str, list[str]] = field(default_factory=dict)


def split_technique_files(
    files_by_technique: Mapping[str, Sequence[str]],
) -> OtrfSplit:
    """Split each technique's recordings by hash rank (deterministic).

    Recordings (host/network siblings collapsed) are ranked and divided;
    ``train``/``test`` carry the expanded file paths. Techniques with
    fewer than two recordings are ``untestable``; non-ATT&CK ids land in
    ``excluded``; then every test side is purged of recordings present on
    any train side, and techniques left with no test recordings become
    untestable.
    """
    split = OtrfSplit()
    owner_count: dict[str, set[str]] = {}
    per_technique_units: dict[str, dict[str, list[str]]] = {}
    for technique in sorted(files_by_technique):
        if not is_attack_id(technique):
            split.excluded[technique] = sorted(set(files_by_technique[technique]))
            continue
        files = sorted(set(files_by_technique[technique]))
        for path in files:
            owner_count.setdefault(path, set()).add(technique)
        units: dict[str, list[str]] = {}
        for path in files:
            units.setdefault(recording_key(path), []).append(path)
        per_technique_units[technique] = units
        if len(units) < 2:
            split.techniques[technique] = TechniqueSplit(
                technique=technique,
                train=tuple(files),
                test=(),
                untestable=True,
            )
            continue
        ranked = sorted(units, key=rank_key)
        n_test = max(1, len(ranked) // 2)
        test_units = ranked[:n_test]
        train_units = ranked[n_test:]
        split.techniques[technique] = TechniqueSplit(
            technique=technique,
            train=tuple(path for unit in train_units for path in units[unit]),
            test=tuple(path for unit in test_units for path in units[unit]),
            untestable=False,
        )

    train_units: set[str] = set()
    for entry in split.techniques.values():
        for path in entry.train:
            train_units.add(recording_key(path))
    for technique, entry in list(split.techniques.items()):
        if entry.untestable or not entry.test:
            continue
        kept = tuple(
            path for path in entry.test if recording_key(path) not in train_units
        )
        if not kept:
            split.techniques[technique] = TechniqueSplit(
                technique=entry.technique,
                train=entry.train,
                test=(),
                untestable=True,
            )
        elif len(kept) != len(entry.test):
            split.techniques[technique] = TechniqueSplit(
                technique=entry.technique,
                train=entry.train,
                test=kept,
                untestable=False,
            )

    split.multi_label_files = {
        path: sorted(owners)
        for path, owners in sorted(owner_count.items())
        if len(owners) > 1
    }
    return split


def otrf_files_by_technique(
    ground_truth: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[str]]:
    """Group OTRF technique-labelled files (data-relative paths) by id."""
    grouped: dict[str, list[str]] = {}
    for rel in sorted(ground_truth):
        label = ground_truth[rel]
        if label.get("dataset") != OTRF_DATASET:
            continue
        if label.get("label_source") != OTRF_METADATA_SOURCE:
            continue
        techniques = label.get("techniques") or []
        for technique in sorted(set(str(item) for item in techniques)):
            grouped.setdefault(technique, []).append(rel)
    return grouped


def summarize(split: OtrfSplit) -> str:
    """One line per technique plus disclosures (counts and lists)."""
    lines = []
    for technique in sorted(split.techniques):
        entry = split.techniques[technique]
        lines.append(
            f"{technique}: train n={len(entry.train)}, "
            f"test n={len(entry.test)}, "
            f"untestable={entry.untestable}"
        )
    lines.append(f"multi-label files: n={len(split.multi_label_files)}")
    for path in sorted(split.multi_label_files):
        lines.append(f"  {path}: {', '.join(split.multi_label_files[path])}")
    lines.append(f"excluded non-ATT&CK ids: n={len(split.excluded)}")
    for technique in sorted(split.excluded):
        lines.append(f"  {technique}: n={len(split.excluded[technique])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", default="data/ground_truth.json")
    args = parser.parse_args(argv)

    truth_path = (REPO_ROOT / args.ground_truth).resolve()
    try:
        truth_path.relative_to(REPO_ROOT)
    except ValueError:
        print("error: --ground-truth must stay inside the repository")
        return 2
    if not truth_path.is_file():
        print(f"error: ground truth missing: {truth_path}")
        return 1
    ground_truth = json.loads(truth_path.read_text(encoding="utf-8"))
    grouped = otrf_files_by_technique(ground_truth)
    split = split_technique_files(grouped)
    testable = sum(1 for entry in split.techniques.values() if not entry.untestable)
    print(
        f"techniques: n={len(split.techniques)} "
        f"({testable} testable, "
        f"{len(split.techniques) - testable} untestable); "
        f"excluded non-ATT&CK ids: n={len(split.excluded)} "
        f"({sum(len(files) for files in split.excluded.values())} files)"
    )
    print(summarize(split))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
