"""Census of the Linux lab archives (benign baseline, no attack).

Usage (from the repo root)::

    uv run python eval/linux_census.py [--archives data/lab-archives]

Reads every ``ossec-archive-*.json.gz`` (and ``*.json``) document, counts
by agent, location, decoder, predecoder program, auditd record type and
rule id, and asks the CURRENT ``corvus.normalize.wazuh`` archive mapper
which documents map and which stay unmapped. Prints counts only (no log
content, no user names, no host names beyond the agent label already in
the report). Every number carries n, the window, and the producing
command.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def iter_archive_docs(
    archives: Path,
) -> tuple[list[Path], int, int, list[dict[str, Any]]]:
    """Read every archive document; return (files, lines, bad, docs).

    ``docs`` holds ``(doc, file, lineno)`` triples for parseable JSON
    objects; ``bad`` counts truncated/non-JSON lines, never raised.
    """
    files = sorted(
        [
            *archives.glob("ossec-archive-*.json"),
            *archives.glob("ossec-archive-*.json.gz"),
        ]
    )
    docs: list[dict[str, Any]] = []
    lines = 0
    bad = 0
    for path in files:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as handle:  # type: ignore[arg-type]
            for lineno, line in enumerate(handle, 1):
                text = line.strip()
                if not text:
                    continue
                lines += 1
                try:
                    doc = json.loads(text)
                except ValueError:
                    bad += 1
                    continue
                if not isinstance(doc, dict):
                    bad += 1
                    continue
                docs.append({"doc": doc, "file": path.name, "lineno": lineno})
    return files, lines, bad, docs


def main(argv: list[str] | None = None) -> int:
    """Run the census and print counts; return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", default="data/lab-archives")
    args = parser.parse_args(argv)

    from corvus.normalize import wazuh

    archives = (REPO_ROOT / args.archives).resolve()
    try:
        archives.relative_to(REPO_ROOT)
    except ValueError:
        print("error: --archives must stay in the repo")
        return 2
    if not archives.is_dir():
        print(f"error: archives missing: {archives}", file=sys.stderr)
        return 1

    files, lines, bad, docs = iter_archive_docs(archives)
    by_agent: Counter[Any] = Counter()
    by_location: Counter[Any] = Counter()
    by_decoder: Counter[Any] = Counter()
    by_predecoder: Counter[Any] = Counter()
    by_audit_type: Counter[Any] = Counter()
    by_rule: Counter[Any] = Counter()
    per_class: Counter[int] = Counter()
    unmapped: Counter[Any] = Counter()
    mapped = 0
    times: list[int] = []
    for entry in docs:
        doc = entry["doc"]
        agent = doc.get("agent")
        if isinstance(agent, dict):
            by_agent[(agent.get("id"), agent.get("name"))] += 1
        else:
            by_agent[(None, None)] += 1
        by_location[doc.get("location")] += 1
        decoder = doc.get("decoder")
        if isinstance(decoder, dict):
            by_decoder[(decoder.get("name"), decoder.get("parent"))] += 1
        else:
            by_decoder[(decoder, None)] += 1
        pre = doc.get("predecoder")
        by_predecoder[pre.get("program_name") if isinstance(pre, dict) else None] += 1
        data = doc.get("data")
        audit = data.get("audit") if isinstance(data, dict) else None
        by_audit_type[audit.get("type") if isinstance(audit, dict) else None] += 1
        rule = doc.get("rule")
        by_rule[rule.get("id") if isinstance(rule, dict) else None] += 1
        try:
            times.append(wazuh.parse_wazuh_time(doc.get("timestamp")))
        except ValueError, TypeError:
            pass
        hit = {"_id": f"{entry['file']}:{entry['lineno']}", "_source": doc}
        try:
            event, key = wazuh.map_archive(hit)
        except ValueError:
            event, key = None, ("error", None)
        if event is None:
            unmapped[key] += 1
        else:
            mapped += 1
            per_class[event.class_uid] += 1

    window = f"{min(times)}..{max(times)}" if times else "empty"
    print(f"files: {len(files)} ({', '.join(p.name for p in files)})")
    print(f"lines: n={lines} (window {window}; bad/non-JSON lines: {bad})")
    print(f"by agent (n={lines}): {dict(sorted(by_agent.items(), key=str))}")
    print(f"by location (n={lines}): {dict(sorted(by_location.items(), key=str))}")
    print(f"by decoder (n={lines}): {dict(sorted(by_decoder.items(), key=str))}")
    print(
        f"by predecoder program (n={lines}): "
        f"{dict(sorted(by_predecoder.items(), key=str))}"
    )
    print(
        f"by auditd record type (n={lines}): "
        f"{dict(sorted(by_audit_type.items(), key=str))}"
    )
    print(f"by rule id (n={lines}): {dict(sorted(by_rule.items(), key=str))}")
    print(
        f"mapped by current normalizer: {mapped} (n={lines}; "
        f"per class: {dict(sorted(per_class.items()))})"
    )
    print(
        f"unmapped by current normalizer (n={lines}): "
        f"{dict(sorted(unmapped.items(), key=str))}"
    )
    print("producing command: uv run python eval/linux_census.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
