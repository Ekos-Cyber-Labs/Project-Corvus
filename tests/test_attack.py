"""Tests for the MITRE ATT&CK dictionary (corvus/attack).

Fixture-first: the mini STIX bundle under tests/fixtures/ is
hand-written (synthetic T9xxx ids, invented names) and covers a live
technique, a sub-technique, a revoked technique with its revoked-by
relationship, a deprecated technique, and a matrix whose tactic order
is deliberately non-alphabetical. One real-data test re-checks the
APT29 day-1 ground truth against the built dictionary and skips when
the compact file has not been built.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvus.attack import (
    AttackDictionary,
    build_compact,
    build_from_files,
    load_dictionary,
)
from corvus.cli import main

FIXTURE = Path("tests/fixtures/mini_attack_bundle.json")


def _compact() -> dict[str, object]:
    bundle = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(bundle, dict)
    return build_compact(bundle)


def _dictionary() -> AttackDictionary:
    return AttackDictionary.from_compact(_compact())


def test_tactic_order_comes_from_matrix_not_alphabet() -> None:
    compact = _compact()
    assert compact["tactic_order"] == ["persistence", "execution", "discovery"]
    assert compact["attack_version"] == "v20.0"
    assert compact["cti_rev"] == "50be388e93819a5d20e71cbaaeccfda157abc846"


def test_build_fields_cover_lifecycle() -> None:
    entries = _compact()["techniques"]
    assert isinstance(entries, dict)
    assert set(entries) == {"T9001", "T9002", "T9002.001", "T9003", "T9004"}
    # Kill-chain phases follow matrix order, not bundle order.
    assert entries["T9001"]["tactics"] == ["execution", "discovery"]  # type: ignore[index]
    sub = entries["T9002.001"]
    assert sub["is_subtechnique"] is True  # type: ignore[index]
    assert sub["parent"] == "T9002"  # type: ignore[index]
    retired = entries["T9003"]
    assert retired["revoked"] is True  # type: ignore[index]
    assert retired["revoked_by"] == "T9001"  # type: ignore[index]
    dropped = entries["T9004"]
    assert dropped["deprecated"] is True  # type: ignore[index]
    assert dropped["revoked_by"] is None  # type: ignore[index]
    assert entries["T9001"]["revoked_by"] is None  # type: ignore[index]


def test_get_is_case_insensitive_strict_and_total() -> None:
    dictionary = _dictionary()
    assert dictionary.get("t9001") is not None
    assert dictionary.get("  T9001 ") is not None
    assert dictionary.get("T9001") is not None
    assert dictionary.get("T9002.001") is not None
    assert dictionary.get("T9001").name == "Synthetic Alpha"  # type: ignore[union-attr]
    for bad in ["T901", "T90010", "T9001.1", "T9001.0001", "X9001", "", "  ", "TT9001"]:
        assert dictionary.get(bad) is None, bad
    assert dictionary.get(None) is None
    assert dictionary.get(9001) is None
    assert dictionary.get("T9999") is None


def test_resolve_follows_revoked_by_to_live() -> None:
    dictionary = _dictionary()
    assert dictionary.get("T9003") is not None  # revoked entry still listed
    resolved = dictionary.resolve("T9003")
    assert resolved is not None
    assert resolved.id == "T9001"
    assert dictionary.resolve("t9003").id == "T9001"  # type: ignore[union-attr]
    live = dictionary.resolve("T9001")
    assert live is not None and live.id == "T9001"
    assert dictionary.resolve("T9004") is None  # deprecated, no replacement
    assert dictionary.resolve("T9999") is None
    assert dictionary.resolve("bogus") is None


def test_technique_tactics_carry_display_names() -> None:
    entry = _dictionary().get("T9001")
    assert entry is not None
    assert [(t.shortname, t.name) for t in entry.tactics] == [
        ("execution", "Execution"),
        ("discovery", "Discovery"),
    ]


def test_build_from_files_round_trip(tmp_path: Path) -> None:
    out = tmp_path / "attack" / "enterprise.json"
    stats = build_from_files(FIXTURE, out)
    assert stats["techniques"] == 5
    assert stats["revoked"] == 1
    assert stats["tactics"] == 3
    assert stats["bytes"] == out.stat().st_size > 0
    before = out.read_bytes()
    reread = load_dictionary(out)
    assert reread.resolve("T9003") is not None
    assert reread.resolve("T9003").id == "T9001"  # type: ignore[union-attr]
    again = build_from_files(FIXTURE, out)
    assert again["bytes"] == stats["bytes"]
    assert out.read_bytes() == before  # rebuild is byte-identical


def test_cli_attack_build(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "enterprise.json"
    assert main(["attack", "build", "--bundle", str(FIXTURE), "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "5 techniques" in text
    assert str(out) in text
    assert load_dictionary(out).get("T9002") is not None


def _real_dictionary() -> AttackDictionary | None:
    target = Path("data/attack/enterprise.json")
    if not target.is_file():
        return None
    return load_dictionary()


def test_ground_truth_ids_resolve_against_real_dictionary() -> None:
    """Every current ground-truth id resolves to a live technique.

    Skips when the compact dictionary has not been built (git-ignored
    data); the fetch + build steps produce it.
    """
    dictionary = _real_dictionary()
    if dictionary is None:
        pytest.skip("compact ATT&CK dictionary not built")
    chain = json.loads(
        Path("eval/apt29_day1_ground_truth.json").read_text(encoding="utf-8")
    )
    problems: list[str] = []
    for step in chain["steps"]:
        for tid in step["techniques"]:
            resolved = dictionary.resolve(tid)
            if resolved is None or resolved.id != tid:
                got = None if resolved is None else resolved.id
                problems.append(f"step {step['step']}: {tid} resolves to {got}")
        for chosen, detail in step["refinements"].items():
            if dictionary.get(detail["refines"]) is None:
                problems.append(
                    f"step {step['step']}: refinement base {detail['refines']} unknown"
                )
            if dictionary.resolve(chosen) is None:
                problems.append(f"step {step['step']}: refined {chosen} not live")
    assert problems == []
    # The plan's revoked ids keep their documented current targets.
    assert dictionary.resolve("T1145") is not None
    assert dictionary.resolve("T1145").id == "T1552.004"  # type: ignore[union-attr]
    assert len(dictionary.tactic_order) == 15
    assert dictionary.tactic_order[0] == "reconnaissance"
    assert dictionary.tactic_order[-1] == "impact"
