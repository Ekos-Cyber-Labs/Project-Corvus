"""Build the compact ATT&CK dictionary from the pinned STIX bundle.

Reads ``data/mitre-cti/enterprise-attack/enterprise-attack.json``
once and writes ``data/attack/enterprise.json``: one entry per
external ATT&CK id with name, tactics, sub-technique linkage,
deprecation/revocation flags and the ``revoked_by`` target resolved
through ``revoked-by`` relationship objects. Tactic order comes from
the bundle's ``x-mitre-matrix`` ``tactic_refs``, never from a
hand-written list.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from corvus.attack.dictionary import normalize_id

__all__ = [
    "ATTACK_VERSION",
    "CTI_REPO",
    "CTI_REV",
    "build_compact",
    "build_from_files",
    "format_summary",
]

#: Pinned ATT&CK release the compact dictionary is built from.
ATTACK_VERSION = "v20.0"
CTI_REPO = "mitre/cti"
CTI_REV = "50be388e93819a5d20e71cbaaeccfda157abc846"


def _external_id(obj: dict[str, object]) -> str | None:
    """Return the ``mitre-attack`` external id of a STIX object, if any."""
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if (
            isinstance(ref, dict)
            and ref.get("source_name") == "mitre-attack"
            and isinstance(ref.get("external_id"), str)
        ):
            return str(ref["external_id"])
    return None


def _matrix_size(matrix: object) -> int:
    """Return the tactic count of a matrix object (0 when malformed)."""
    refs = matrix.get("tactic_refs") if isinstance(matrix, dict) else None
    return len(refs) if isinstance(refs, list) else 0


def build_compact(bundle: dict[str, object]) -> dict[str, object]:
    """Build the compact dictionary mapping from a decoded STIX bundle."""
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX bundle lacks an objects list")

    tactics: dict[str, dict[str, str]] = {}
    by_stix: dict[str, str] = {}
    techniques: dict[str, dict[str, object]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type")
        stix_id = obj.get("id")
        if kind == "x-mitre-tactic" and isinstance(stix_id, str):
            short = obj.get("x_mitre_shortname")
            name = obj.get("name")
            if isinstance(short, str) and isinstance(name, str):
                tactics[stix_id] = {"shortname": short, "name": name}
        elif kind == "attack-pattern" and isinstance(stix_id, str):
            ext_id = _external_id(obj)
            if ext_id is None or normalize_id(ext_id) != ext_id:
                continue
            phases = obj.get("kill_chain_phases")
            phase_names: list[str] = []
            if isinstance(phases, list):
                for phase in phases:
                    if (
                        isinstance(phase, dict)
                        and phase.get("kill_chain_name") == "mitre-attack"
                        and isinstance(phase.get("phase_name"), str)
                    ):
                        phase_names.append(str(phase["phase_name"]))
            by_stix[stix_id] = ext_id
            techniques[ext_id] = {
                "name": str(obj.get("name")),
                "tactics": phase_names,
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "deprecated": bool(obj.get("x_mitre_deprecated")),
                "revoked": bool(obj.get("revoked")),
            }

    matrices = [
        obj
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-matrix"
    ]
    if not matrices:
        raise ValueError("STIX bundle holds no x-mitre-matrix")
    # The bundle carries one matrix; if several ever appear, the one
    # naming the most tactics is the Enterprise kill chain.
    matrix = max(matrices, key=_matrix_size)
    refs = matrix.get("tactic_refs")
    if not isinstance(refs, list) or not refs:
        raise ValueError("x-mitre-matrix lacks tactic_refs")
    tactic_order: list[str] = []
    tactic_names: dict[str, str] = {}
    for ref in refs:
        entry = tactics.get(ref) if isinstance(ref, str) else None
        if entry is None:
            raise ValueError(f"matrix tactic_ref {ref!r} has no tactic object")
        tactic_order.append(entry["shortname"])
        tactic_names[entry["shortname"]] = entry["name"]
    rank = {short: index for index, short in enumerate(tactic_order)}

    revoked_by: dict[str, str] = {}
    parents: dict[str, str] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        rel = obj.get("relationship_type")
        if rel not in ("revoked-by", "subtechnique-of"):
            continue
        source = obj.get("source_ref")
        target = obj.get("target_ref")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if source not in by_stix or target not in by_stix:
            continue
        if rel == "revoked-by":
            revoked_by[by_stix[source]] = by_stix[target]
        else:
            parents[by_stix[source]] = by_stix[target]

    entries: dict[str, dict[str, object]] = {}
    for ext_id, info in techniques.items():
        raw_phases = info["tactics"]
        phase_list = raw_phases if isinstance(raw_phases, list) else []
        ordered = sorted(
            {
                phase
                for phase in phase_list
                if isinstance(phase, str) and phase in tactic_names
            },
            key=lambda phase: rank[phase],
        )
        entries[ext_id] = {
            "name": info["name"],
            "tactics": ordered,
            "is_subtechnique": info["is_subtechnique"],
            "parent": parents.get(ext_id),
            "deprecated": info["deprecated"],
            "revoked": info["revoked"],
            "revoked_by": revoked_by.get(ext_id),
        }
    return {
        "attack_version": ATTACK_VERSION,
        "cti_repo": CTI_REPO,
        "cti_rev": CTI_REV,
        "tactic_order": tactic_order,
        "tactics": tactic_names,
        "techniques": entries,
    }


def build_from_files(
    bundle_path: str | Path, out_path: str | Path
) -> dict[str, object]:
    """Build the compact file from ``bundle_path`` into ``out_path``.

    Returns run stats (technique/revoked counts, seconds, bytes).
    The output is written atomically, so a crash never leaves a
    half-written dictionary behind.
    """
    src = Path(bundle_path)
    dst = Path(out_path)
    started = time.perf_counter()
    bundle = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(bundle, dict):
        raise ValueError(f"{src} does not hold a JSON object")
    compact = build_compact(bundle)
    payload = json.dumps(compact, indent=2, sort_keys=True) + "\n"
    elapsed = time.perf_counter() - started
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".part")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.replace(tmp, dst)
    entries = compact["techniques"]
    assert isinstance(entries, dict)
    revoked = sum(1 for e in entries.values() if e.get("revoked"))  # type: ignore[union-attr]
    return {
        "techniques": len(entries),
        "revoked": revoked,
        "tactics": len(compact["tactic_order"]),  # type: ignore[arg-type]
        "seconds": elapsed,
        "bytes": dst.stat().st_size,
        "out": str(dst),
    }


def format_summary(stats: dict[str, object]) -> str:
    """Render one human-readable build summary line."""
    seconds = float(stats["seconds"])  # type: ignore[arg-type]
    return (
        f"wrote {stats['out']}: {stats['techniques']} techniques "
        f"({stats['revoked']} revoked) across {stats['tactics']} tactics "
        f"in {seconds:.1f}s, {stats['bytes']} bytes"
    )
