"""Tests for the eval harness gates (fast, no replay store needed).

The benign gate must fail on a synthetic Critical incident and pass
below Critical; the leakage check must fail on a planted
ground-truth string and pass on clean rows. All fixtures are
hand-written; no dataset content is used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from eval.harness import (
    atomic_coverage,
    benign_gate_fails,
    chain_step_coverage,
    compare_inputs,
    format_deltas,
    git_tree_status,
    read_baseline,
)
from eval.leakage import scan_dumps


def _incident(severity_id: int) -> dict[str, object]:
    """One synthetic incident row with the given severity."""
    return {
        "correlation_key": f"corr-test-{severity_id}",
        "severity_id": severity_id,
        "severity_floor": min(severity_id, 5),
    }


def test_benign_gate_fails_on_synthetic_critical() -> None:
    tripping = benign_gate_fails([_incident(3), _incident(5)])
    assert len(tripping) == 1
    assert tripping[0]["severity_id"] == 5


def test_benign_gate_fails_on_fatal_and_passes_below_critical() -> None:
    assert len(benign_gate_fails([_incident(6)])) == 1
    assert benign_gate_fails([_incident(1), _incident(4)]) == []


def test_leakage_fails_on_planted_technique_id() -> None:
    dump = '{"process": {"cmd_line": "run T1003 now"}, "product": "Corvus"}'
    hits = scan_dumps([dump], ["security-datasets"], ["T1003"])
    assert any("T1003" in hit for hit in hits)


def test_leakage_fails_on_planted_dataset_name() -> None:
    dump = '{"file": "security-datasets/datasets/atomic/x.zip"}'
    hits = scan_dumps([dump], ["security-datasets"], [])
    assert hits != []


def test_leakage_finds_unlisted_technique_token() -> None:
    dump = r'{"cmd_line": "C:\\art\\atomics\\T1218.005\\x.ps1"}'
    hits = scan_dumps([dump], [], [])
    assert any("T1218.005" in hit for hit in hits)


def test_leakage_passes_clean_rows_without_technique_check() -> None:
    dumps = [
        '{"process": {"cmd_line": "powershell.exe -NoProfile -Command Get-Service"}}',
        '{"product": "Corvus", "log_name": "sigma"}',
    ]
    assert scan_dumps(dumps, ["security-datasets"], ["T1003"]) == []
    assert scan_dumps(dumps, ["security-datasets"], [], check_techniques=False) == []


def test_shared_helper_rejects_planted_string_for_both_callers() -> None:
    """One planted dump fails the tests' and the harness' call shapes.

    The tests call ``scan_dumps`` with substrings plus ids in one pass;
    the harness splits markers (datasets/files/windows, no techniques)
    from ids (technique check on) and exempts only flagged rows. The
    same planted dump must trip both shapes, so neither can drift past
    what the other catches.
    """
    dump = (
        '{"file": "security-datasets/datasets/atomic/x.zip", '
        '"cmd_line": "run T1003 now"}'
    )
    test_shape = scan_dumps([dump], ["T1003", "security-datasets"], ["T1003"])
    assert test_shape != []
    harness_meta = scan_dumps([dump], ["security-datasets"], [], check_techniques=False)
    harness_ids = scan_dumps([dump], [], ["T1003"])
    assert harness_meta != []
    assert harness_ids != []


def test_compare_inputs_flags_a_changed_generator_seed() -> None:
    baseline = {
        "rules": {"evaluated": 10},
        "datasets": {"replay_events": 100},
        "benign": {"seed": 7},
        "correlation": {"session_gap_minutes": 30},
        "ground_truth": {"label_sources": ["otrf-metadata"]},
    }
    same = dict(baseline)
    assert compare_inputs(baseline, same) == []
    changed = dict(baseline)
    changed["benign"] = {"seed": 8}
    assert compare_inputs(baseline, changed) == ["benign"]


def test_format_deltas_reports_per_chain_step_coverage() -> None:
    chain_before = {
        "chain_id": "apt29-day1",
        "best_covered_n": 2,
        "all_covered_n": 3,
        "steps_n": 10,
    }
    baseline = {
        "benign_incidents": 4,
        "benign_critical": 0,
        "atomic_match": 10,
        "findings": 100,
        "incidents": 20,
        "in_band_events": 5,
        "chains": [chain_before],
    }
    chain_after = dict(chain_before)
    chain_after["best_covered_n"] = 3
    chain_after["all_covered_n"] = 8
    current = dict(baseline)
    current["chains"] = [chain_after]
    lines = format_deltas(baseline, current)
    assert any("apt29-day1" in line and "best" in line for line in lines)
    assert any("apt29-day1" in line and "all" in line for line in lines)
    assert not any("detected" in line and "yes" in line for line in lines)


def test_cli_eval_run_missing_replay_dir_exits_nonzero(tmp_path) -> None:
    from corvus.cli import main as cli_main

    missing = str(tmp_path / "no-such-store")
    assert cli_main(["eval", "run", "--replay-dir", missing]) == 2


def test_read_baseline_outside_repo_reads_file(tmp_path) -> None:
    candidate = tmp_path / "baseline.json"
    candidate.write_text('{"findings": 1}')
    baseline, provenance = read_baseline(candidate)
    assert baseline == {"findings": 1}
    assert provenance == "file"


def test_read_baseline_ignores_uncommitted_in_repo_file() -> None:
    from eval.harness import REPO_ROOT

    candidate = REPO_ROOT / "eval" / "reports" / "_test_untracked_baseline.json"
    assert not candidate.exists()
    baseline, provenance = read_baseline(candidate)
    assert baseline is None
    assert provenance == "none"


def _finding_row(
    uid: str, techniques: list[str], when_ms: int = 1_700_000_000_000
) -> dict[str, object]:
    """One hand-written finding row for the file under test.

    Expansion mirrors ``load_finding_rows``: stated ids plus the true
    parent of each sub-technique.
    """
    from corvus.attack import normalize_id

    stated = [normalize_id(technique) or technique for technique in techniques]
    expanded = set(stated)
    expanded.update(technique.split(".")[0] for technique in list(expanded))
    return {
        "uid": uid,
        "time": when_ms,
        "rule_id": "rule-test",
        "level": "High",
        "host": "web01.example.com",
        "file": "datasets/test/exact.zip",
        "techniques": expanded,
        "finding_json": "{}",
    }


def test_atomic_coverage_splits_exact_and_parent_only() -> None:
    ground_truth: dict[str, Any] = {
        "datasets/test/exact.zip": {
            "dataset": "security-datasets",
            "label_source": "otrf-metadata",
            "techniques": ["T1003.001"],
        },
        "datasets/test/parent.zip": {
            "dataset": "security-datasets",
            "label_source": "otrf-metadata",
            "techniques": ["T1003.002"],
        },
        "datasets/test/none.zip": {
            "dataset": "security-datasets",
            "label_source": "otrf-metadata",
            "techniques": ["T1003.001"],
        },
        "datasets/test/parent-gt-parent.zip": {
            "dataset": "security-datasets",
            "label_source": "otrf-metadata",
            "techniques": ["T1055"],
        },
        "datasets/test/parent-gt-sub.zip": {
            "dataset": "security-datasets",
            "label_source": "otrf-metadata",
            "techniques": ["T1055"],
        },
    }
    parent_row = _finding_row("parent-1", ["T1003.001"])
    parent_row["file"] = "datasets/test/parent.zip"
    missing_row = _finding_row("none-1", ["T1083"])
    missing_row["file"] = "datasets/test/none.zip"
    gt_parent_row = _finding_row("gt-parent-1", ["T1055"])
    gt_parent_row["file"] = "datasets/test/parent-gt-parent.zip"
    gt_sub_row = _finding_row("gt-sub-1", ["T1055.001"])
    gt_sub_row["file"] = "datasets/test/parent-gt-sub.zip"
    rows = [
        _finding_row("exact-1", ["T1003.001"]),
        parent_row,
        missing_row,
        gt_parent_row,
        gt_sub_row,
    ]
    result = atomic_coverage(ground_truth, rows, set(ground_truth))
    assert result["with_match_n"] == 4
    assert result["with_exact_n"] == 3
    assert result["with_parent_only_n"] == 1
    by_file = {row["file"]: row for row in result["per_file"]}
    assert by_file["datasets/test/exact.zip"]["match_kind"] == "exact"
    assert by_file["datasets/test/parent.zip"]["match_kind"] == "parent-only"
    assert by_file["datasets/test/none.zip"]["match_kind"] == "none"
    assert by_file["datasets/test/parent.zip"]["matched_techniques"] == ["T1003"]
    gt_parent = by_file["datasets/test/parent-gt-parent.zip"]
    assert gt_parent["match_kind"] == "exact"
    assert gt_parent["matched_techniques"] == ["T1055"]
    gt_sub = by_file["datasets/test/parent-gt-sub.zip"]
    assert gt_sub["match_kind"] == "exact"
    assert gt_sub["matched_techniques"] == ["T1055"]


def _test_attack() -> object:
    from corvus.attack import AttackDictionary

    compact: dict[str, object] = {
        "tactics": {
            "credential-access": {"name": "Credential Access", "id": "TA0006"},
            "discovery": {"name": "Discovery", "id": "TA0007"},
        },
        "tactic_order": ["credential-access", "discovery"],
        "techniques": {
            "T1003": {
                "name": "OS Credential Dumping",
                "tactics": ["credential-access"],
                "is_subtechnique": False,
                "parent": None,
                "deprecated": False,
                "revoked": False,
                "revoked_by": None,
            },
            "T1003.001": {
                "name": "LSASS Memory",
                "tactics": ["credential-access"],
                "is_subtechnique": True,
                "parent": "T1003",
                "deprecated": False,
                "revoked": False,
                "revoked_by": None,
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactics": ["discovery"],
                "is_subtechnique": False,
                "parent": None,
                "deprecated": False,
                "revoked": False,
                "revoked_by": None,
            },
        },
    }
    return AttackDictionary.from_compact(compact)


def test_chain_step_reports_in_window_gap_details() -> None:
    chain: dict[str, Any] = {
        "chain_id": "test-chain",
        "dataset_file": "datasets/test/chain.zip",
        "window": {"start": "2020-05-02T00:00:00Z", "end": "2020-05-02T04:00:00Z"},
        "steps": [
            {
                "step": 1,
                "name": "Covered",
                "window": {
                    "start": "2020-05-02T01:00:00Z",
                    "end": "2020-05-02T02:00:00Z",
                },
                "techniques": ["T1003.001"],
            },
            {
                "step": 2,
                "name": "Findings Without Match",
                "window": {
                    "start": "2020-05-02T02:00:00Z",
                    "end": "2020-05-02T03:00:00Z",
                },
                "techniques": ["T1003.001"],
            },
            {
                "step": 3,
                "name": "Empty",
                "window": {
                    "start": "2020-05-02T03:00:00Z",
                    "end": "2020-05-02T04:00:00Z",
                },
                "techniques": ["T1003.001"],
            },
        ],
    }
    attack = _test_attack()
    covered = _finding_row("finding-1", ["T1003.001"], 1_588_383_000_000)
    covered["file"] = "datasets/test/chain.zip"
    plain = _finding_row("finding-2", ["T1083"], 1_588_386_600_000)
    plain["file"] = "datasets/test/chain.zip"
    result = chain_step_coverage(chain, [covered, plain], [{"finding-1"}], attack)
    assert result["best_covered_n"] == 1
    assert result["all_covered_n"] == 1
    by_step = {step["step"]: step for step in result["steps"]}
    assert by_step[1]["covered_by_best"] is True
    assert by_step[1]["findings_in_window_n"] == 1
    assert by_step[1]["window_has_technique_match"] is True
    assert by_step[2]["covered_by_all"] is False
    assert by_step[2]["findings_in_window_n"] == 1
    assert by_step[2]["window_has_technique_match"] is False
    assert by_step[3]["covered_by_all"] is False
    assert by_step[3]["findings_in_window_n"] == 0
    assert by_step[3]["window_has_technique_match"] is False


def _git(repo: Path, *args: str) -> None:
    import subprocess

    subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        check=True,
        timeout=30,
    )


def test_git_tree_status_temp_repo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory) / "repo"
        repo.mkdir()
        _git(repo, "init")
        _git(
            repo,
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "--allow-empty",
            "-m",
            "init",
        )
        assert git_tree_status(repo) == (False, 0)
        tracked = repo / "tracked.txt"
        tracked.write_text("change", encoding="utf-8")
        _git(repo, "add", "tracked.txt")
        _git(
            repo,
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "-m",
            "add",
        )
        assert git_tree_status(repo) == (False, 0)
        tracked.write_text("dirty", encoding="utf-8")
        assert git_tree_status(repo) == (True, 1)
        latest = repo / "eval" / "reports" / "latest.md"
        latest.parent.mkdir(parents=True, exist_ok=True)
        latest.write_text("report", encoding="utf-8")
        dirty, count = git_tree_status(repo)
        assert dirty is True
        assert count == 1


def test_git_tree_status_not_a_repo(tmp_path) -> None:
    assert git_tree_status(tmp_path) == (False, 0)
