"""Runtime MITRE ATT&CK Enterprise dictionary.

The dictionary is keyed by external ATT&CK id (``T####`` with an
optional ``.###`` sub-technique suffix). It is built once from the
pinned STIX bundle into a small compact JSON file (see
:mod:`corvus.attack.build`); the 49 MB bundle is never parsed per
request. This module only loads the compact form.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "AttackDictionary",
    "Tactic",
    "Technique",
    "load_dictionary",
    "normalize_id",
]

#: Strict ATT&CK id shape: ``T`` + 4 digits, optional ``.`` + 3 digits.
#: ``re.ASCII`` keeps ``\\d`` to ASCII digits only. Matching is done on
#: uppercased input; ids never contain lowercase.
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?$", re.ASCII)


def normalize_id(raw: object) -> str | None:
    """Return the canonical id for ``raw`` or None when it is not an id.

    Strips surrounding whitespace and uppercases, so lookups are
    case-insensitive. Anything that is not a string, or not exactly the
    ``T####[.###]`` shape, returns None: unknown or malformed input is
    never guessed at.
    """
    if not isinstance(raw, str):
        return None
    candidate = raw.strip().upper()
    if not TECHNIQUE_ID.fullmatch(candidate):
        return None
    return candidate


@dataclass(frozen=True)
class Tactic:
    """One ATT&CK tactic: shortname (``credential-access``) and display name."""

    shortname: str
    name: str


@dataclass(frozen=True)
class Technique:
    """One dictionary entry keyed by external ATT&CK id."""

    id: str
    name: str
    tactics: tuple[Tactic, ...]
    is_subtechnique: bool
    parent: str | None
    deprecated: bool
    revoked: bool
    revoked_by: str | None


class AttackDictionary:
    """Exact-key ATT&CK lookup over a compact dictionary file."""

    def __init__(
        self,
        techniques: dict[str, Technique],
        tactic_order: tuple[str, ...],
    ) -> None:
        self._techniques = techniques
        self._tactic_order = tactic_order

    @property
    def tactic_order(self) -> tuple[str, ...]:
        """Kill-chain tactic shortnames in matrix order."""
        return self._tactic_order

    def __len__(self) -> int:
        return len(self._techniques)

    def get(self, raw: object) -> Technique | None:
        """Return the entry for ``raw`` or None.

        Case-insensitive; strict id shape; unknown ids return None and
        are never guessed at.
        """
        key = normalize_id(raw)
        if key is None:
            return None
        return self._techniques.get(key)

    def resolve(self, raw: object) -> Technique | None:
        """Return the live technique for ``raw`` or None.

        Follows ``revoked_by`` links to the current id (for example
        ``T1145`` resolves to ``T1552.004``). Unknown ids, deprecated
        ids with no replacement, broken links and revoked cycles all
        return None.
        """
        entry = self.get(raw)
        if entry is None:
            return None
        seen = {entry.id}
        while entry.revoked:
            if entry.revoked_by is None or entry.revoked_by in seen:
                return None
            seen.add(entry.revoked_by)
            entry = self._techniques.get(entry.revoked_by)
            if entry is None:
                return None
        if entry.deprecated:
            return None
        return entry

    @classmethod
    def from_compact(cls, mapping: dict[str, object]) -> AttackDictionary:
        """Build a dictionary from a decoded compact JSON mapping."""
        tactics_raw = mapping.get("tactics")
        if not isinstance(tactics_raw, dict):
            raise ValueError("compact attack dictionary lacks a tactics map")
        tactics = {
            str(short): Tactic(shortname=str(short), name=str(name))
            for short, name in tactics_raw.items()
        }
        order_raw = mapping.get("tactic_order")
        if not isinstance(order_raw, list) or not all(
            isinstance(item, str) for item in order_raw
        ):
            raise ValueError("compact attack dictionary lacks a tactic order")
        order = tuple(str(item) for item in order_raw)
        unknown = [short for short in order if short not in tactics]
        if unknown:
            raise ValueError(f"tactic order names unknown tactics: {unknown}")
        entries_raw = mapping.get("techniques")
        if not isinstance(entries_raw, dict):
            raise ValueError("compact attack dictionary lacks techniques")
        techniques: dict[str, Technique] = {}
        for key, value in entries_raw.items():
            if not isinstance(value, dict):
                raise ValueError(f"technique {key!r} is not an object")
            if normalize_id(key) != key:
                raise ValueError(f"technique key {key!r} is not a canonical id")
            tactic_names: list[Tactic] = []
            phase_raw = value.get("tactics")
            if not isinstance(phase_raw, list):
                raise ValueError(f"technique {key} lacks a tactics list")
            for short in phase_raw:
                if not isinstance(short, str) or short not in tactics:
                    raise ValueError(f"technique {key} names unknown tactic {short!r}")
                tactic_names.append(tactics[short])
            parent = value.get("parent")
            revoked_by = value.get("revoked_by")
            if parent is not None and not isinstance(parent, str):
                raise ValueError(f"technique {key} has a bad parent")
            if revoked_by is not None and not isinstance(revoked_by, str):
                raise ValueError(f"technique {key} has a bad revoked_by")
            techniques[key] = Technique(
                id=key,
                name=str(value.get("name")),
                tactics=tuple(tactic_names),
                is_subtechnique=bool(value.get("is_subtechnique")),
                parent=parent,
                deprecated=bool(value.get("deprecated")),
                revoked=bool(value.get("revoked")),
                revoked_by=revoked_by,
            )
        return cls(techniques, order)


def load_dictionary(path: str | Path | None = None) -> AttackDictionary:
    """Load the compact dictionary from ``path`` (default location).

    The default is the same cwd-relative ``data/attack/enterprise.json``
    the ``corvus attack build`` CLI writes.
    """
    target = Path(path) if path is not None else Path("data/attack/enterprise.json")
    mapping = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(mapping, dict):
        raise ValueError(f"{target} does not hold a JSON object")
    return AttackDictionary.from_compact(mapping)
