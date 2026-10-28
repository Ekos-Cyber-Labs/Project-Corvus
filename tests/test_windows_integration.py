"""Integration over real replay files: counts and classes only, never content.

Each test is skipped when `data/` holds no file of the needed format. No
test asserts anything about event content, only structural invariants:
every record is either mapped or counted, classes stay in the mapped set,
uids are unique opaque hex, and times are past the OCSF floor.
"""

import re
import tarfile
import zipfile
from pathlib import Path

import pytest

from corvus.normalize.ocsf import MIN_TIME_MS
from corvus.normalize.windows import WindowsReadResult, read_dataset_file

EVTX_DIR = Path("data/evtx-attack-samples")
OTRF_WINDOWS = Path("data/security-datasets/datasets/atomic/windows")

ALLOWED_CLASSES = {1007, 4001, 1001, 3002, 1006, 1009, 201001, 201002, 201004}
UID_PATTERN = re.compile(r"^[0-9a-f]{16}$")


def _first_evtx() -> Path | None:
    if not EVTX_DIR.is_dir():
        return None
    return next(
        (path for path in sorted(EVTX_DIR.rglob("*.evtx")) if path.is_file()), None
    )


def _first_host_zip() -> Path | None:
    if not OTRF_WINDOWS.is_dir():
        return None
    for path in sorted(OTRF_WINDOWS.rglob("*.zip")):
        try:
            with zipfile.ZipFile(path) as archive:
                names = [
                    info.filename for info in archive.infolist() if not info.is_dir()
                ]
        except zipfile.BadZipFile:
            continue
        if any(Path(name).suffix.lower() == ".json" for name in names):
            return path
    return None


def _first_pcap_zip() -> Path | None:
    if not OTRF_WINDOWS.is_dir():
        return None
    for path in sorted(OTRF_WINDOWS.rglob("*.zip")):
        try:
            with zipfile.ZipFile(path) as archive:
                names = [
                    info.filename for info in archive.infolist() if not info.is_dir()
                ]
        except zipfile.BadZipFile:
            continue
        if names and all(Path(name).suffix.lower() != ".json" for name in names):
            return path
    return None


def _first_tar_gz() -> Path | None:
    if not OTRF_WINDOWS.is_dir():
        return None
    return next(
        (path for path in sorted(OTRF_WINDOWS.rglob("*.tar.gz")) if path.is_file()),
        None,
    )


def _unknown_share(result: WindowsReadResult) -> float:
    """Share of records counted under an unknown channel (counts only)."""
    total = len(result.events) + sum(result.unmapped.values())
    if total == 0:
        return 0.0
    unknown = sum(
        count for (channel, _), count in result.unmapped.items() if channel == "unknown"
    )
    return unknown / total


def _check_invariants(result: WindowsReadResult, total: int) -> None:
    """Every record is mapped or counted; ids, classes and times are sane."""
    assert len(result.events) + sum(result.unmapped.values()) == total
    assert all(
        isinstance(channel, str) and isinstance(event_id, int)
        for channel, event_id in result.unmapped
    )
    assert {event.class_uid for event in result.events} <= ALLOWED_CLASSES
    uids = [event.metadata.uid or "" for event in result.events]
    assert len(set(uids)) == len(uids)
    assert all(UID_PATTERN.match(uid) for uid in uids)
    assert all(event.time >= MIN_TIME_MS for event in result.events)
    assert all(event.metadata.log_name for event in result.events)
    assert _unknown_share(result) < 0.05


def test_evtx_file_counts_and_classes() -> None:
    path = _first_evtx()
    if path is None:
        pytest.skip("no .evtx under data/evtx-attack-samples/")
    from evtx import PyEvtxParser

    total = sum(1 for _ in PyEvtxParser(str(path)).records_json())
    assert total > 0
    result = read_dataset_file(path, dataset_rel=path.as_posix())
    _check_invariants(result, total)


def test_host_archive_counts_and_classes() -> None:
    path = _first_host_zip()
    if path is None:
        pytest.skip("no host .zip with JSON under data/security-datasets/")
    total = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir() or Path(info.filename).suffix.lower() != ".json":
                continue
            with archive.open(info) as stream:
                total += sum(1 for line in stream if line.strip())
    assert total > 0
    result = read_dataset_file(path, dataset_rel=path.as_posix())
    _check_invariants(result, total)


def test_pcap_archive_is_unsupported() -> None:
    path = _first_pcap_zip()
    if path is None:
        pytest.skip("no pcap-only .zip under data/security-datasets/")
    result = read_dataset_file(path, dataset_rel=path.as_posix())
    assert result.events == []
    assert result.unmapped == {}
    assert result.unsupported >= 1


def test_tar_gz_archive_yields_mapped_events() -> None:
    path = _first_tar_gz()
    if path is None:
        pytest.skip("no .tar.gz under data/security-datasets/")
    total = 0
    with tarfile.open(path, mode="r|gz") as archive:
        for member in archive:
            if not member.isfile() or Path(member.name).suffix.lower() != ".json":
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            with stream:
                total += sum(1 for line in stream if line.strip())
    assert total > 0
    result = read_dataset_file(path, dataset_rel=path.as_posix())
    _check_invariants(result, total)
    assert len(result.events) > 0
