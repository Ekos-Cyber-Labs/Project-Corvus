"""Offline tests for scripts/fetch_datasets.py helpers (no network)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

# scripts/ is not a package; load by path so tests stay import-safe.
_spec = importlib.util.spec_from_file_location(
    "fetch_datasets", Path("scripts/fetch_datasets.py")
)
assert _spec is not None and _spec.loader is not None
fetch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch)


def test_wanted_filters_to_windows_atomic_subset() -> None:
    paths = [
        "Credential Access/synth_t1098.evtx",
        "Execution/synth_t1059.evtx",
        "README.md",
        "Winlogbeat-Bulk-Read.ps1",
        "UACME_synth.evtx",
        "datasets/atomic/windows/execution/host/synth.zip",
        "datasets/atomic/_metadata/SDWIN-000000000001.yaml",
        "datasets/atomic/linux/execution/host/synth.zip",
        "datasets/compound/synth.zip",
    ]
    assert fetch.wanted(paths, ["Credential Access", "Execution"], True) == [
        "Credential Access/synth_t1098.evtx",
        "Execution/synth_t1059.evtx",
        "UACME_synth.evtx",
    ]
    assert fetch.wanted(
        paths, ["datasets/atomic/windows", "datasets/atomic/_metadata"], False
    ) == [
        "datasets/atomic/_metadata/SDWIN-000000000001.yaml",
        "datasets/atomic/windows/execution/host/synth.zip",
    ]


def test_wanted_keeps_only_sample_extensions() -> None:
    paths = [
        "Execution/synth_t1059.evtx",
        "Execution/synth_capture.pcap",
        "Execution/synth_notes.log",
        "Execution/notes.md",
        "Execution/notes.txt",
        "Execution/synth_trace.etl",
        "synth_root.pcap",
        "UACME_synth.evtx",
    ]
    assert fetch.wanted(paths, ["Execution"], True, [".evtx", ".etl"]) == [
        "Execution/synth_t1059.evtx",
        "Execution/synth_trace.etl",
        "UACME_synth.evtx",
    ]


def test_download_percent_encodes_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, str] = {}

    class FakeResponse:
        done = False

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def read(self, size: int = -1) -> bytes:
            if self.done:
                return b""
            self.done = True
            return b"synth-bytes"

    def fake_urlopen(request: object, timeout: int = 0) -> FakeResponse:
        seen["url"] = str(request.get_full_url())  # type: ignore[union-attr]
        return FakeResponse()

    monkeypatch.setattr(fetch.urllib.request, "urlopen", fake_urlopen)
    dest = tmp_path / "Command and Control" / "synth A&B.evtx"
    fetch.download("example/repo", "abc123", "Command and Control/synth A&B.evtx", dest)
    assert dest.read_bytes() == b"synth-bytes"
    url = seen["url"]
    assert "Command%20and%20Control/synth%20A%26B.evtx" in url
    assert "%2F" not in url


def test_checksums_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "checksums.txt"
    target.write_text(
        "# comment\n\nabc123  data/a.bin\n   \ndeadbeef  data/b.bin\n", encoding="utf-8"
    )
    assert fetch.read_checksums(target) == {
        "data/a.bin": "abc123",
        "data/b.bin": "deadbeef",
    }
    fetch.write_checksums(target, {"data/b.bin": "deadbeef", "data/a.bin": "abc123"})
    lines = target.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    assert "deadbeef  data/b.bin" in lines
    assert fetch.read_checksums(target) == {
        "data/a.bin": "abc123",
        "data/b.bin": "deadbeef",
    }


def test_sha256_of(tmp_path: Path) -> None:
    import hashlib

    target = tmp_path / "a.bin"
    target.write_bytes(b"corvus-synth-fixture")
    expected = hashlib.sha256(b"corvus-synth-fixture").hexdigest()
    assert fetch.sha256_of(target) == expected


def test_wanted_picks_only_apt29_day1_host_zip() -> None:
    paths = [
        "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
        "datasets/compound/apt29/day1/pcaps/SCRANTON.zip",
        "datasets/compound/apt29/day1/zeek/combined_zeek.log",
        "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip",
        "datasets/atomic/windows/execution/host/synth.zip",
    ]
    prefixes = [
        "datasets/atomic/windows",
        "datasets/atomic/_metadata",
        "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
    ]
    assert fetch.wanted(paths, prefixes, False) == [
        "datasets/atomic/windows/execution/host/synth.zip",
        "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
    ]
    # The compound file is fetched at the same OTRF pin as the atomic files.
    otrf = [d for d in fetch.DATASETS if d["name"] == "security-datasets"][0]
    assert (
        "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip" in otrf["prefixes"]
    )  # type: ignore[operator]


def test_dataset_pins_are_well_formed() -> None:
    assert len(fetch.DATASETS) == 3
    for dataset in fetch.DATASETS:
        assert dataset["repo"] and dataset["dest"] and dataset["prefixes"]
        assert re.fullmatch(r"[0-9a-f]{40}", str(dataset["rev"])), dataset
        # dest is joined onto the data dir; a "data/" prefix would nest data/.
        assert not str(dataset["dest"]).startswith("data/")
    by_name = {str(dataset["name"]): dataset for dataset in fetch.DATASETS}
    assert set(by_name) == {"evtx-attack-samples", "security-datasets", "mitre-cti"}


def test_mitre_cti_fetches_only_bundle_and_license() -> None:
    paths = [
        "enterprise-attack/enterprise-attack.json",
        "LICENSE.txt",
        "mobile-attack/mobile-attack.json",
        "ics-attack/ics-attack.json",
        "some-guide.md",
    ]
    mitre = [d for d in fetch.DATASETS if d["name"] == "mitre-cti"][0]
    assert mitre["rev"] == "50be388e93819a5d20e71cbaaeccfda157abc846"
    assert fetch.wanted(paths, list(mitre["prefixes"]), False) == [  # type: ignore[arg-type]
        "LICENSE.txt",
        "enterprise-attack/enterprise-attack.json",
    ]
