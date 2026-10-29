"""Write Detection Findings into the replay store.

Findings land in ``findings/<slug>.parquet`` next to the per-file
``events/`` and ``provenance/`` tables, one file per loaded input
slug (an input with no findings gets an empty table with the same
schema, so "no findings" stays distinguishable from "never run").
Each file is written to ``<slug>.parquet.tmp`` and moved into place
with :func:`os.replace`, exactly like the event files, so a run
killed mid-write leaves no truncated file behind and a re-run emits
the same deterministic uids with no duplicates.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pyarrow as pa
import pyarrow.parquet as pq

from corvus.adapters.replay.schema import (
    FINDINGS_SCHEMA,
    finding_to_row,
    findings_dir,
    provenance_dir,
    slug_for_rel,
)

if TYPE_CHECKING:
    from corvus.attack.dictionary import AttackDictionary
    from corvus.detect.engine import MatchedEvent
    from corvus.detect.rules import CompiledRule

__all__ = ["WriteSummary", "format_write_summary", "write_findings"]


class WriteSummary:
    """Counts for one findings write (printed by the CLI)."""

    def __init__(self) -> None:
        self.files: int = 0
        self.findings: int = 0
        self.unmatched_provenance: int = 0


def _uid_to_file(replay_dir: str | Path) -> dict[str, str]:
    """Map every stored event uid to its data-relative input path."""
    directory = provenance_dir(replay_dir)
    mapping: dict[str, str] = {}
    if not directory.is_dir():
        return mapping
    for path in sorted(directory.glob("*.parquet")):
        table = pq.read_table(path, columns=["uid", "file"])
        for record in table.to_pylist():
            if record["uid"] is not None:
                mapping[str(record["uid"])] = str(record["file"])
    return mapping


def write_findings(
    replay_dir: str | Path,
    compiled: list[CompiledRule],
    matches: dict[str, set[str]],
    infos: dict[str, MatchedEvent],
    attack: AttackDictionary,
    attack_version: str,
) -> WriteSummary:
    """Build and store one finding per rule match; return counts."""
    from corvus.detect.findings import build_finding

    summary = WriteSummary()
    by_rule = {rule.rule_id: rule for rule in compiled}
    uid_to_file = _uid_to_file(replay_dir)
    out_dir = findings_dir(replay_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    staged: dict[str, list[dict[str, Any]]] = {}
    for slug_file in {file for file in uid_to_file.values()}:
        staged.setdefault(slug_for_rel(slug_file), [])
    for rule_id in sorted(matches):
        rule = by_rule.get(rule_id)
        if rule is None:
            continue
        for uid in sorted(matches[rule_id]):
            info = infos.get(uid)
            data_rel = uid_to_file.get(uid)
            if info is None or data_rel is None:
                summary.unmatched_provenance += 1
                continue
            finding = build_finding(rule, info, attack, attack_version)
            staged[slug_for_rel(data_rel)].append(
                finding_to_row(finding, rule.rule_id, rule.level)
            )

    for slug, rows in sorted(staged.items()):
        target = out_dir / f"{slug}.parquet"
        tmp = out_dir / f"{slug}.parquet.tmp"
        try:
            with pq.ParquetWriter(tmp, FINDINGS_SCHEMA) as writer:
                if rows:
                    table = pa.table(
                        {
                            name: pa.array(
                                [row.get(name) for row in rows],
                                type=FINDINGS_SCHEMA.field(name).type,
                            )
                            for name in FINDINGS_SCHEMA.names
                        }
                    )
                    writer.write_table(table)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        os.replace(tmp, target)
        summary.files += 1
        summary.findings += len(rows)
    return summary


def format_write_summary(summary: WriteSummary, replay_dir: str | Path) -> str:
    """Render the findings-write summary printed by ``corvus replay detect``."""
    return (
        f"wrote {summary.findings} findings to {summary.files} files "
        f"under {findings_dir(replay_dir)}"
    )
