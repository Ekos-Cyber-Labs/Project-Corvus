"""Tests for eval/ground_truth.py using tiny synthetic samples.

All file names and YAML snippets below are hand-written fakes that
exercise the naming/metadata formats; no real dataset content is used.
"""

from pathlib import Path

from eval.ground_truth import (
    build_ground_truth,
    build_otrf_index,
    evtx_techniques_for_filename,
    normalize_technique,
    otrf_key_for_link,
    parse_otrf_metadata,
    tactics_for_folder,
)


def test_normalize_technique() -> None:
    assert normalize_technique("T1098", None) == "T1098"
    assert normalize_technique("t1059", "005") == "T1059.005"
    assert normalize_technique("T1059", "") == "T1059"
    assert normalize_technique("T1059", '"001"') == "T1059.001"
    assert normalize_technique("TXYZ", None) is None
    assert normalize_technique("T105", None) is None
    assert normalize_technique("T1059", "00") is None


def test_evtx_filename_tokens() -> None:
    assert evtx_techniques_for_filename("synth_logon_t1098.evtx") == ["T1098"]
    assert evtx_techniques_for_filename("SYNTH_T1186_Doppelganging.evtx") == ["T1186"]
    assert evtx_techniques_for_filename("synth_T1059.001_launcher.evtx") == [
        "T1059.001"
    ]
    assert evtx_techniques_for_filename("synth_exec_t1059.005.evtx") == ["T1059.005"]
    # Only "." separates a sub-technique; "-" and "_" do not.
    assert evtx_techniques_for_filename("synth_T1059-001_dash.evtx") == ["T1059"]
    assert evtx_techniques_for_filename("synth_T1059_001_under.evtx") == ["T1059"]


def test_evtx_filename_token_boundaries() -> None:
    # Trailing event id after "_" is not a sub-technique.
    assert evtx_techniques_for_filename("t1098_4794.evtx") == ["T1098"]
    assert evtx_techniques_for_filename("T1003.001.evtx") == ["T1003.001"]
    assert evtx_techniques_for_filename("Win_4985_T1186_x.evtx") == ["T1186"]
    # Glued to a letter or digit on the left: no token.
    assert evtx_techniques_for_filename("synth_AT1098.evtx") == []
    assert evtx_techniques_for_filename("synth_1098T.evtx") == []
    # Trailing letters are allowed by the pattern; trailing digits are not.
    assert evtx_techniques_for_filename("synth_T1098x.evtx") == ["T1098"]
    assert evtx_techniques_for_filename("synth_T1098_1.evtx") == ["T1098"]


def test_evtx_filename_multiple_and_missing() -> None:
    assert evtx_techniques_for_filename("synth_T1110_T1078_attempt.evtx") == [
        "T1078",
        "T1110",
    ]
    assert evtx_techniques_for_filename("synth_dcsync_4662.evtx") == []
    assert evtx_techniques_for_filename("synth_log_4624.evtx") == []
    # Short sub-technique: base id still counts, fragment is dropped.
    assert evtx_techniques_for_filename("synth_T1059.00_short.evtx") == ["T1059"]


def test_tactics_for_folder() -> None:
    assert tactics_for_folder("Credential Access") == ["Credential Access"]
    assert tactics_for_folder("credential_access") == ["Credential Access"]
    assert tactics_for_folder("Command and Control") == ["Command and Control"]
    assert tactics_for_folder("AutomatedTestingTools") == []
    assert tactics_for_folder("Other") == []
    assert tactics_for_folder("Synth Made Up") == []


SYNTH_YAML_SINGLE = """\
title: Synthetic VBS Launcher
id: SYNTH-0001
platform:
- Windows
type: atomic
attack_mappings:
  - technique: T1059
    sub-technique: "005"
    tactics:
      - TA0002
files:
- type: Host
  link: https://example.com/datasets/atomic/windows/execution/host/synth_launcher.zip
"""

SYNTH_YAML_BARE_AND_MULTI = """\
title: Synthetic Admin Group
id: SYNTH-0002
attack_mappings:
- technique: T1069
  tactics:
    - TA0007
- technique: T1087
  sub-technique: '001'
  tactics:
    - TA0007
files:
  - type: Host
    link: https://example.com/datasets/atomic/windows/discovery/host/synth_group.zip
  - type: Network
    link: https://example.com/datasets/atomic/windows/discovery/network/synth_group.zip
"""


def test_parse_otrf_metadata_single() -> None:
    meta = parse_otrf_metadata(SYNTH_YAML_SINGLE)
    assert meta.dataset_id == "SYNTH-0001"
    assert meta.techniques == ["T1059.005"]
    assert meta.links == [
        "https://example.com/datasets/atomic/windows/execution/host/synth_launcher.zip"
    ]


def test_parse_otrf_metadata_bare_and_multi() -> None:
    meta = parse_otrf_metadata(SYNTH_YAML_BARE_AND_MULTI)
    assert meta.dataset_id == "SYNTH-0002"
    assert meta.techniques == ["T1069", "T1087.001"]
    assert len(meta.links) == 2


def test_parse_otrf_metadata_ignores_bad_technique() -> None:
    meta = parse_otrf_metadata(
        "id: SYNTH-0003\nattack_mappings:\n- technique: TXYZ\nfiles:\n"
    )
    assert meta.techniques == []


def test_otrf_key_for_link() -> None:
    assert (
        otrf_key_for_link("https://example.com/datasets/atomic/windows/x/host/a.zip")
        == "x/host/a.zip"
    )
    assert otrf_key_for_link("https://example.com/other/a.zip") == "a.zip"


def _write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_build_ground_truth_end_to_end(tmp_path: Path) -> None:
    data = tmp_path / "data"
    _write(data / "evtx-attack-samples/Credential Access/synth_logon_t1098.evtx")
    _write(data / "evtx-attack-samples/Credential Access/synth_plain_4624.evtx")
    _write(data / "evtx-attack-samples/Other/synth_other.evtx")
    _write(
        data
        / "security-datasets/datasets/atomic/windows/execution/host/synth_launcher.zip"
    )
    _write(
        data
        / "security-datasets/datasets/atomic/windows/discovery/host/synth_group.zip"
    )
    _write(
        data
        / "security-datasets/datasets/atomic/windows/discovery/host/synth_orphan.zip"
    )
    _write(
        data / "security-datasets/datasets/atomic/_metadata/SDWIN-999999999901.yaml",
        SYNTH_YAML_SINGLE,
    )
    _write(
        data / "security-datasets/datasets/atomic/_metadata/SDWIN-999999999902.yaml",
        SYNTH_YAML_BARE_AND_MULTI,
    )

    mapping = build_ground_truth(data)

    token = mapping["evtx-attack-samples/Credential Access/synth_logon_t1098.evtx"]
    assert token.dataset == "evtx-attack-samples"
    assert token.techniques == ["T1098"]
    assert token.tactics == ["Credential Access"]
    assert token.label_source == "evtx-filename"

    folder = mapping["evtx-attack-samples/Credential Access/synth_plain_4624.evtx"]
    assert folder.dataset == "evtx-attack-samples"
    assert folder.techniques == []
    assert folder.tactics == ["Credential Access"]
    assert folder.label_source == "evtx-folder"

    other = mapping["evtx-attack-samples/Other/synth_other.evtx"]
    assert other.techniques == []
    assert other.tactics == []
    assert other.label_source == "evtx-folder"

    launcher = mapping[
        "security-datasets/datasets/atomic/windows/execution/host/synth_launcher.zip"
    ]
    assert launcher.dataset == "security-datasets"
    assert launcher.techniques == ["T1059.005"]
    assert launcher.tactics == ["Execution"]
    assert launcher.label_source == "otrf-metadata"

    group = mapping[
        "security-datasets/datasets/atomic/windows/discovery/host/synth_group.zip"
    ]
    assert group.techniques == ["T1069", "T1087.001"]
    assert group.tactics == ["Discovery"]
    assert group.label_source == "otrf-metadata"

    orphan = mapping[
        "security-datasets/datasets/atomic/windows/discovery/host/synth_orphan.zip"
    ]
    assert orphan.techniques == []
    assert orphan.tactics == ["Discovery"]
    assert orphan.label_source == "otrf-metadata"


def test_build_otrf_index_unions_same_target(tmp_path: Path) -> None:
    meta_dir = tmp_path / "meta"
    meta_dir.mkdir()
    (meta_dir / "SDWIN-000000000001.yaml").write_text(
        "id: SDWIN-000000000001\nattack_mappings:\n- technique: T1003\n"
        '  sub-technique: "001"\nfiles:\n- type: Host\n'
        "  link: https://example.com/datasets/atomic/windows/x/host/synth_a.zip\n",
        encoding="utf-8",
    )
    (meta_dir / "SDWIN-000000000002.yaml").write_text(
        "id: SDWIN-000000000002\nattack_mappings:\n- technique: T1003\n"
        '  sub-technique: "002"\nfiles:\n- type: Host\n'
        "  link: https://example.com/datasets/atomic/windows/x/host/synth_a.zip\n",
        encoding="utf-8",
    )
    index = build_otrf_index(meta_dir)
    assert index["x/host/synth_a.zip"] == {"T1003.001", "T1003.002"}
