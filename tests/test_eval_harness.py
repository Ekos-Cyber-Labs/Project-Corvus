"""Tests for the eval harness gates (fast, no replay store needed).

The benign gate must fail on a synthetic Critical incident and pass
below Critical; the leakage check must fail on a planted
ground-truth string and pass on clean rows. All fixtures are
hand-written; no dataset content is used.
"""

from __future__ import annotations

from eval.harness import (
    benign_gate_fails,
    check_leakage,
    compare_inputs,
    format_deltas,
    read_baseline,
)


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
    hits = check_leakage([dump], ["security-datasets"], ["T1003"])
    assert any("T1003" in hit for hit in hits)


def test_leakage_fails_on_planted_dataset_name() -> None:
    dump = '{"file": "security-datasets/datasets/atomic/x.zip"}'
    hits = check_leakage([dump], ["security-datasets"], [])
    assert hits != []


def test_leakage_finds_unlisted_technique_token() -> None:
    dump = r'{"cmd_line": "C:\\art\\atomics\\T1218.005\\x.ps1"}'
    hits = check_leakage([dump], [], [])
    assert any("T1218.005" in hit for hit in hits)


def test_leakage_passes_clean_rows_without_technique_check() -> None:
    dumps = [
        '{"process": {"cmd_line": "powershell.exe -NoProfile -Command Get-Service"}}',
        '{"product": "Corvus", "log_name": "sigma"}',
    ]
    assert check_leakage(dumps, ["security-datasets"], ["T1003"]) == []
    assert check_leakage(dumps, ["security-datasets"], [], check_techniques=False) == []


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
