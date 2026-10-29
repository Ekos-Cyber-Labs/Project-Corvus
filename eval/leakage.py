"""Shared ground-truth leakage assertions (eval-only helpers).

One importable helper used by ``tests/test_replay.py``,
``tests/test_chain_ground_truth.py`` and the ``corvus eval run`` gate,
so the three cannot drift: every caller scans serialized rows for
forbidden substrings (case-insensitive) and, unless the caller disables
it, forbidden technique ids, and requires ``find_technique_ids`` to be
empty. Callers choose which markers to pass and scrub detector output
(finding attacks, incident techniques) plus loader-flagged in-band
rows before calling.
"""

from __future__ import annotations


def scan_dumps(
    dumps: list[str],
    forbidden_substrings: list[str],
    forbidden_ids: list[str],
    *,
    check_techniques: bool = True,
) -> list[str]:
    """Scan serialized rows for ground-truth leakage (pure, testable).

    Returns the hit descriptions (empty when clean).
    """
    from corvus.normalize.technique_ids import find_technique_ids

    hits: list[str] = []
    for index, dump in enumerate(dumps):
        lowered = dump.lower()
        for marker in forbidden_substrings:
            if marker and marker.lower() in lowered:
                hits.append(f"row {index}: forbidden substring {marker!r}")
        if not check_techniques:
            continue
        for technique in forbidden_ids:
            if technique and technique in dump:
                hits.append(f"row {index}: forbidden technique id {technique!r}")
        if find_technique_ids(dump):
            hits.append(f"row {index}: technique token {find_technique_ids(dump)!r}")
    return hits
