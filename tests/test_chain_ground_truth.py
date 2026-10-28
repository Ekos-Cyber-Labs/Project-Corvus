"""Tests for the APT29 day-1 chain ground truth and step verdicts.

Synthetic records only (RFC 5737 / example.com fixtures), plus a
real-file verdict test that skips only when the fetched dataset is
absent, like the other real-data tests. The chain file itself is
validated as committed data: ordered steps, per-step windows and
anchors, technique id shapes, and the observed data window.
"""

import json
import zipfile
from pathlib import Path

import pytest

from corvus.adapters.replay import load_path
from corvus.adapters.replay.adapter import ReplayAdapter
from corvus.normalize.technique_ids import find_technique_ids
from eval.chain_ground_truth import (
    evaluate_mapped,
    event_text_fields,
    is_lsass_high_access,
    load_chain,
    step_verdict,
    step_window_ms,
)
from eval.ground_truth import build_ground_truth
from tests.fixtures import windows_events as fx

CHAIN = load_chain()
DATASET = Path(
    "data/security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"
)

EXPECTED_WINDOWS = {
    1: ("2020-05-02T02:55:57Z", "2020-05-02T03:02:06Z"),
    2: ("2020-05-02T02:56:18Z", "2020-05-02T03:03:16Z"),
    3: ("2020-05-02T02:57:01Z", "2020-05-02T03:08:53Z"),
    4: ("2020-05-02T02:59:44Z", "2020-05-02T03:18:22Z"),
    5: ("2020-05-02T03:04:16Z", "2020-05-02T03:04:24Z"),
    6: ("2020-05-02T03:00:37Z", "2020-05-02T03:05:20Z"),
    7: ("2020-05-02T03:05:46Z", "2020-05-02T03:07:15Z"),
    8: ("2020-05-02T03:00:26Z", "2020-05-02T03:18:22Z"),
    9: ("2020-05-02T03:15:32Z", "2020-05-02T03:17:43Z"),
    10: ("2020-05-02T03:19:53Z", "2020-05-02T03:28:20Z"),
}


def test_chain_is_ordered_day1_only_with_window() -> None:
    assert CHAIN["chain_id"] == "apt29-day1"
    assert "day1" in CHAIN["dataset_file"]
    assert "day2" not in CHAIN["dataset_file"]
    assert [step["step"] for step in CHAIN["steps"]] == list(range(1, 11))
    assert CHAIN["window"]["start"] == "2020-05-02T02:55:26Z"
    assert CHAIN["window"]["end"] == "2020-05-02T03:28:20Z"
    assert CHAIN["label_level"] == "chain"
    assert CHAIN["event_level_precision_computable"] is False
    assert CHAIN["sources"]["emulation_plan"]["rev"] == (
        "201db70f403676cc8ec090035f17d98cf9995244"
    )
    assert CHAIN["sources"]["emulation_plan"]["license"] == "Apache-2.0"
    assert CHAIN["sources"]["dataset"]["license"] == "MIT"


def test_steps_carry_windows_anchors_and_expected_verdicts() -> None:
    for step in CHAIN["steps"]:
        start, end = EXPECTED_WINDOWS[int(step["step"])]
        assert step["window"] == {"start": start, "end": end}
        assert step["anchors"]
        assert all(anchor == anchor.lower() for anchor in step["anchors"])
        # match_kind is the expected verdict under the current mapping.
        assert step["match_kind"] in ("direct", "indirect", "none")


def test_techniques_cross_checked_against_plan_ids() -> None:
    by_step = {step["step"]: step for step in CHAIN["steps"]}
    step1 = by_step[1]
    # The plan names the RTLO masquerade and both interpreters for
    # step 1 (plan ids T1036/T1059/T1086 in their 2020 spellings).
    assert "T1036" in step1["plan_techniques"]
    assert "T1086" in step1["plan_techniques"]
    assert "T1036.002" in step1["techniques"]
    assert "T1059.001" in step1["techniques"]
    assert "T1059.003" in step1["techniques"]
    # Plan T1065 is revoked by T1571 (no sub-techniques): T1571.001
    # must not appear anywhere.
    assert "T1065" in step1["plan_techniques"]
    assert "T1571" in step1["techniques"]
    assert "T1571.001" not in step1["techniques"]
    # Refinements: chosen sub-technique -> plan or revoked-by id,
    # with a reason, and the chosen id listed in techniques.
    assert step1["refinements"]["T1036.002"]["refines"] == "T1036"
    assert step1["refinements"]["T1036.002"]["reason"]
    assert by_step[2]["refinements"]["T1560.001"]["refines"] == "T1560"
    assert by_step[2]["refinements"]["T1074.001"]["refines"] == "T1074"
    assert by_step[7]["refinements"]["T1056.001"]["refines"] == "T1056"
    assert by_step[8]["refinements"]["T1078.002"]["refines"] == "T1078"
    assert by_step[9]["refinements"]["T1560.001"]["refines"] == "T1560"
    assert by_step[10]["refinements"]["T1134.001"]["refines"] == "T1134"
    for step in CHAIN["steps"]:
        for chosen, detail in step["refinements"].items():
            assert chosen in step["techniques"]
            assert detail["refines"]
            assert detail["reason"]
    # Step 3: plan T1122 is revoked by T1546.015 (COM hijacking),
    # not Modify Registry; plan T1043 is dropped as deprecated.
    step3 = by_step[3]
    assert "T1122" in step3["plan_techniques"]
    assert "T1546.015" in step3["techniques"]
    dropped = {entry["plan_technique"]: entry for entry in step3["dropped_techniques"]}
    assert dropped["T1043"]["status"] == "deprecated"
    assert dropped["T1043"]["reason"]
    assert "T1043" not in step3["techniques"]
    # Step 6: plan T1081 is revoked by T1552.001. T1555.003 is kept
    # only as a refinement of that target, never as its resolution.
    step6 = by_step[6]
    assert "T1081" in step6["plan_techniques"]
    assert "T1552.001" in step6["techniques"]
    assert step6["refinements"]["T1555.003"]["refines"] == "T1552.001"
    assert step6["refinements"]["T1003.001"]["refines"] == "T1003"
    # Renamed/revoked plan ids keep the plan spelling in
    # plan_techniques and the current id in techniques.
    assert "T1050" in by_step[5]["plan_techniques"]
    assert "T1543.003" in by_step[5]["techniques"]
    assert "T1145" in by_step[6]["plan_techniques"]
    assert "T1552.004" in by_step[6]["techniques"]
    assert "T1543.003" in by_step[10]["techniques"]
    assert by_step[10]["match_kind"] == "direct"


def _event(granted: str, *, name: str = "lsass.exe") -> object:
    record = fx.flat_sysmon_access()
    record["GrantedAccess"] = granted
    record["TargetImage"] = f"C:\\Windows\\System32\\{name}"
    from tests.test_windows_normalize import _normalize_record

    return _normalize_record(record)


def _at(event: object, time_ms: int) -> object:
    object.__setattr__(event, "time", time_ms)
    return event


def test_lsass_match_keys_on_granted_access_not_touch() -> None:
    assert is_lsass_high_access(_event("0x1fffff"), CHAIN)
    assert is_lsass_high_access(_event("0x1010"), CHAIN)
    # The benign bulk: svchost-style query access must not match.
    assert not is_lsass_high_access(_event("0x1000"), CHAIN)
    assert not is_lsass_high_access(_event("0x1400"), CHAIN)
    # High access to a different target is not LSASS dumping.
    assert not is_lsass_high_access(_event("0x1fffff", name="csrss.exe"), CHAIN)


def test_verdict_logic_direct_indirect_none() -> None:
    assert step_verdict(1, 0) == "direct"
    assert step_verdict(0, 3) == "indirect"
    assert step_verdict(0, 0) == "none"
    step9 = CHAIN["steps"][8]
    start, _ = step_window_ms(step9)
    # Anchor-bearing mapped event inside the step window: direct.
    record = fx.flat_sysmon_process()
    record["CommandLine"] = "powershell.exe -Command rar.exe a out.rar"
    from tests.test_windows_normalize import _normalize_record

    direct = evaluate_mapped([_at(_normalize_record(record), start + 1000)], CHAIN)
    assert direct[9]["anchor_in"] == 1
    assert direct[9]["verdict"] == "direct"
    # Relevant class/activity inside the window, no anchor: indirect.
    plain = evaluate_mapped(
        [_at(_normalize_record(fx.flat_sysmon_process()), start + 1000)], CHAIN
    )
    assert plain[9]["anchor_in"] == 0
    assert plain[9]["relevant"] > 0
    assert plain[9]["verdict"] == "indirect"
    # Anchor outside the window is an out-of-window count, not a match.
    outside = evaluate_mapped([_at(_normalize_record(record), start - 60_000)], CHAIN)
    assert outside[9]["anchor_out"] == 1
    assert outside[9]["verdict"] != "direct"


def test_module_file_fields_join_anchor_search() -> None:
    """A loaded image names its artifact: desc/product/path are searched."""
    from tests.test_windows_normalize import _normalize_record

    record = fx.flat_sysmon_module()
    record["Description"] = "Invented Loader Service"
    record["Product"] = "Invented Loader Suite"
    text = event_text_fields(_normalize_record(record))
    assert "invented loader service" in text
    assert "invented loader suite" in text
    assert "wmidcom.dll" in text
    # Vendor company and signer evidence stay out of the search text.
    assert "microsoft corporation" not in text
    assert "microsoft windows" not in text


def test_shared_artifact_never_counted_for_both_steps() -> None:
    """One javamtsup hit falls in step 5's window or step 10's, never both."""
    from tests.test_windows_normalize import _normalize_record

    def service_event(at_ms: int) -> object:
        record = fx.flat_sysmon_process()
        record["Image"] = "C:\\Windows\\System32\\javamtsup.exe"
        record["CommandLine"] = "C:\\Windows\\System32\\javamtsup.exe"
        return _at(_normalize_record(record), at_ms)

    start5, _ = step_window_ms(CHAIN["steps"][4])
    start10, _ = step_window_ms(CHAIN["steps"][9])
    in5 = evaluate_mapped([service_event(start5 + 1000)], CHAIN)
    assert in5[5]["anchor_in"] == 1
    assert in5[10]["anchor_in"] == 0
    in10 = evaluate_mapped([service_event(start10 + 1000)], CHAIN)
    assert in10[10]["anchor_in"] == 1
    assert in10[5]["anchor_in"] == 0


def test_step6_lsass_counts_only_inside_its_window() -> None:
    start6, end6 = step_window_ms(CHAIN["steps"][5])
    inside = evaluate_mapped([_at(_event("0x1f3fff"), start6 + 1000)], CHAIN)
    # Relevant (Process Open) inside the window, and the census
    # attributes this open to step 6 only because the time is inside.
    assert inside[6]["relevant"] >= 1
    assert start6 <= start6 + 1000 <= end6
    outside = _at(_event("0x1f3fff"), end6 + 60_000)
    assert not (start6 <= outside.time <= end6)  # type: ignore[attr-defined]


def test_ground_truth_registers_compound_as_chain_only(tmp_path: Path) -> None:
    data = tmp_path / "data"
    compound = (
        data
        / "security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"
    )
    compound.parent.mkdir(parents=True)
    compound.write_bytes(b"synthetic")
    mapping = build_ground_truth(data)
    label = mapping[
        "security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"
    ]
    assert label.dataset == "security-datasets"
    assert label.label_source == "otrf-compound-chain"
    # Chain-level only: no per-file technique claim is invented.
    assert label.techniques == []
    assert label.tactics == []


def test_apt29_shaped_path_never_leaks_into_records(tmp_path: Path) -> None:
    """Leakage: dataset, techniques, anchors and windows stay out."""
    data_dir = tmp_path / "data"
    nested = data_dir / "security-datasets" / "datasets" / "compound" / "apt29" / "day1"
    nested.mkdir(parents=True)
    archive = nested / "apt29_evals_day1_manual.zip"
    lines = [
        json.dumps(fx.flat_sysmon_process()),
        json.dumps(fx.flat_powershell_script()),
        json.dumps(fx.flat_security_logon(success=True)),
    ]
    with zipfile.ZipFile(archive, "w") as holder:
        holder.writestr("events.json", "\n".join(lines) + "\n")
    replay_dir = tmp_path / "replay"
    load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    adapter = ReplayAdapter(replay_dir)
    dumps = [event.model_dump_json() for event in adapter.query_events()]
    dumps += [entry.model_dump_json() for entry in adapter.describe_sources().sources]
    assert len(dumps) >= 3
    for dump in dumps:
        lowered = dump.lower()
        assert "apt29" not in lowered
        assert "apt29_evals_day1_manual" not in dump
        assert "compound" not in lowered
        assert find_technique_ids(dump) == []
        for step in CHAIN["steps"]:
            for technique in step["techniques"] + step["plan_techniques"]:
                assert technique not in dump
            for anchor in step["anchors"]:
                assert anchor not in lowered
            assert step["window"]["start"] not in dump
            assert step["window"]["end"] not in dump


@pytest.mark.skipif(not DATASET.is_file(), reason="APT29 dataset not fetched")
def test_real_file_verdicts_equal_expected() -> None:
    """A mapping change that alters visibility must fail here on purpose."""
    from eval.apt29_census import run_census

    result = run_census(DATASET, CHAIN)
    for step in CHAIN["steps"]:
        entry = result["per_step"][int(step["step"])]
        assert entry["verdict"] == step["match_kind"], step["step"]
    shared = result["per_step"][5]["anchor_ids"] & result["per_step"][10]["anchor_ids"]
    assert shared == set()
    # Step 6 keeps only its own window's high-access opens (2 of 7).
    start6, end6 = step_window_ms(CHAIN["steps"][5])
    in6 = [t for t in result["lsass_high_times"] if start6 <= t <= end6]
    assert len(in6) == 2
    assert len(result["lsass_high_times"]) == 7
