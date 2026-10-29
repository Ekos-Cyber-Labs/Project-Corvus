"""Tests for the deterministic OTRF train/test split.

All paths and technique ids below are hand-written fakes; no real dataset
content is used. The split unit is a recording (host/network siblings
collapsed), ranked by hash, never on both sides; single-recording
techniques are untestable and non-ATT&CK ids are excluded and reported.
"""

from __future__ import annotations

import hashlib

from eval.train_test_split import (
    is_attack_id,
    otrf_files_by_technique,
    rank_key,
    recording_key,
    split_technique_files,
)


def _host(name: str) -> str:
    return f"security-datasets/datasets/atomic/windows/x/host/{name}"


def _net(name: str) -> str:
    return f"security-datasets/datasets/atomic/windows/x/network/{name}"


def test_recording_key_collapses_host_and_network() -> None:
    assert recording_key(_host("synth_a.zip")) == recording_key(_net("synth_a.zip"))
    assert recording_key(_host("synth_a.zip")) == (
        "security-datasets/datasets/atomic/windows/x/synth_a.zip"
    )
    assert recording_key(
        "security-datasets/datasets/atomic/windows/ghost/host/synth_a.zip"
    ) == ("security-datasets/datasets/atomic/windows/ghost/synth_a.zip")


def test_siblings_never_land_on_opposite_sides() -> None:
    files = [_host("synth_a.zip"), _net("synth_a.zip"), _host("synth_b.zip")]
    entry = split_technique_files({"T1003": files}).techniques["T1003"]
    assert not entry.untestable
    sides = {path: ("train" if path in entry.train else "test") for path in files}
    assert sides[_host("synth_a.zip")] == sides[_net("synth_a.zip")]
    assert set(entry.train) | set(entry.test) == set(files)
    assert set(entry.train) & set(entry.test) == set()


def test_two_files_from_one_recording_are_untestable() -> None:
    entry = split_technique_files(
        {"T1078": [_host("synth_a.zip"), _net("synth_a.zip")]}
    ).techniques["T1078"]
    assert entry.untestable
    assert len(entry.test) == 0
    assert set(entry.train) == {_host("synth_a.zip"), _net("synth_a.zip")}


def test_single_file_technique_is_untestable_and_not_duplicated() -> None:
    lonely = _host("synth_lonely.zip")
    entry = split_technique_files({"T1098": [lonely]}).techniques["T1098"]
    assert entry.untestable
    assert list(entry.train) == [lonely]
    assert list(entry.test) == []


def test_split_is_deterministic_and_hash_ranked_by_recording() -> None:
    files = [_host(f"synth_{letter}.zip") for letter in "abcd"]
    first = split_technique_files({"T1003": files})
    second = split_technique_files({"T1059": files, "T1003": files})
    assert first.techniques["T1003"] == second.techniques["T1003"]
    units = sorted({recording_key(path) for path in files}, key=rank_key)
    assert rank_key(units[0]) == hashlib.sha256(units[0].encode()).hexdigest()
    entry = first.techniques["T1003"]
    assert not entry.untestable
    assert {recording_key(path) for path in entry.test} == set(units[:2])
    assert {recording_key(path) for path in entry.train} == set(units[2:])


def test_t0000_is_excluded_and_reported() -> None:
    split = split_technique_files(
        {
            "T0000": [_host("synth_placeholder.zip")],
            "T1003": [_host("synth_a.zip"), _host("synth_b.zip")],
        }
    )
    assert "T0000" not in split.techniques
    assert split.excluded == {"T0000": [_host("synth_placeholder.zip")]}
    assert not is_attack_id("T0000")
    assert not is_attack_id("T0000.000")
    assert not is_attack_id("nota-technique")
    assert is_attack_id("T1003")
    assert is_attack_id("T1003.001")


def test_no_recording_is_train_for_one_technique_and_test_for_another() -> None:
    shared = _host("synth_shared.zip")
    split = split_technique_files(
        {
            # One recording shared across techniques plus two recordings
            # each, so every technique starts testable before the purge.
            "T1069": [shared, _host("synth_c.zip"), _host("synth_e.zip")],
            "T1087.001": [shared, _host("synth_d.zip"), _host("synth_f.zip")],
        }
    )
    assert split.multi_label_files == {shared: ["T1069", "T1087.001"]}
    train_units: set[str] = set()
    for entry in split.techniques.values():
        train_units.update(recording_key(path) for path in entry.train)
    for entry in split.techniques.values():
        for path in entry.test:
            assert recording_key(path) not in train_units, (
                f"{path} tests {entry.technique} while training elsewhere"
            )


def test_purge_emptied_test_side_becomes_untestable() -> None:
    # By hash rank, T1110 tests only the shared recording while T1069
    # trains it, so the purge empties T1110's test side and it turns
    # untestable (names pinned by hash probe; ranks are deterministic).
    split = split_technique_files(
        {
            "T1069": [_host("psh.zip"), _host("pc00.zip"), _host("pe00.zip")],
            "T1110": [_host("psh.zip"), _host("po00.zip")],
        }
    )
    assert _host("psh.zip") in split.techniques["T1069"].train
    purged = split.techniques["T1110"]
    assert purged.untestable
    assert purged.test == ()
    assert _host("po00.zip") in purged.train


def test_otrf_files_by_technique_filters_label_sources() -> None:
    good = _host("synth_good.zip")
    ground_truth = {
        good: {
            "dataset": "security-datasets",
            "techniques": ["T1059.005"],
            "tactics": ["Execution"],
            "label_source": "otrf-metadata",
        },
        _host("synth_orphan.zip"): {
            "dataset": "security-datasets",
            "techniques": [],
            "tactics": ["Discovery"],
            "label_source": "otrf-folder",
        },
        "evtx-attack-samples/Execution/synth_evil.evtx": {
            "dataset": "evtx-attack-samples",
            "techniques": ["T1059"],
            "tactics": ["Execution"],
            "label_source": "evtx-filename",
        },
    }
    grouped = otrf_files_by_technique(ground_truth)
    assert grouped == {"T1059.005": [good]}
