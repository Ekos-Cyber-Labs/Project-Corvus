"""Tests for the synthetic benign Windows baseline.

The generator output is declared synthetic; every record below is invented
(RFC 5737 addresses, ``example.com`` hosts). Determinism is pinned per
seed, and every generated record must normalize through the real
flat-layout extractor with zero unknown/unmapped counts and pass the OCSF
conformance check.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from corvus.adapters.replay.schema import serialize_ocsf
from corvus.normalize.conformance import check_record
from corvus.normalize.ocsf import OcsfEvent
from corvus.normalize.windows import (
    UnmappedEvent,
    WindowsReadStats,
    extract_json_parts,
    iter_dataset_file,
    make_uid,
    normalize_event,
    sanitize_record,
)
from eval.benign_windows import (
    BASE_24H,
    BUNDLE_DATE_TIME,
    MEMBER_NAME,
    bundle_name,
    generate,
    scaled_count,
    write_bundle,
)
from eval.benign_windows import (
    main as benign_main,
)


def _normalize_record(record: dict[str, Any], lineno: int) -> OcsfEvent:
    """Normalize one flat record exactly as the replay loader does."""
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, lineno
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid("benign-test", record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )


def test_generator_deterministic_for_seed() -> None:
    first = generate(seed=7, hosts=4, hours=24)
    second = generate(seed=7, hosts=4, hours=24)
    assert first == second
    assert len(first) > 0
    assert generate(seed=8, hosts=4, hours=24) != first


def test_bundle_roundtrip_stable_bytes(tmp_path: Path) -> None:
    out = tmp_path / bundle_name(hosts=2, hours=6, seed=7)
    records = generate(seed=7, hosts=2, hours=6)
    write_bundle(records, out)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out2 = tmp_path / "again.zip"
    write_bundle(generate(seed=7, hosts=2, hours=6), out2)
    assert hashlib.sha256(out2.read_bytes()).hexdigest() == digest
    with zipfile.ZipFile(out) as bundle:
        assert bundle.namelist() == [MEMBER_NAME]
        lines = bundle.read(MEMBER_NAME).decode("utf-8").splitlines()
    assert len(lines) == len(records)


def test_bundle_bytes_ignore_the_wall_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    records = generate(seed=7, hosts=1, hours=1)
    out_early = tmp_path / "early.zip"
    out_late = tmp_path / "late.zip"
    monkeypatch.setattr(time, "time", lambda: 0.0)
    write_bundle(records, out_early)
    monkeypatch.setattr(time, "time", lambda: 4102444800.0)
    write_bundle(records, out_late)
    assert out_early.read_bytes() == out_late.read_bytes()
    with zipfile.ZipFile(out_early) as bundle:
        assert bundle.getinfo(MEMBER_NAME).date_time == BUNDLE_DATE_TIME


def test_volume_scales_with_hours() -> None:
    assert scaled_count(20, 24) == 20
    assert scaled_count(20, 6) == 5
    assert scaled_count(2, 6) == 1
    assert scaled_count(1, 1) == 1
    full = generate(seed=7, hosts=4, hours=24)
    assert len(full) == 4 * sum(BASE_24H.values()) + 4 * (
        BASE_24H["task_def"] + BASE_24H["service_install"]
    )
    short = generate(seed=7, hosts=4, hours=6)
    assert 0 < len(short) < len(full)
    pairs = {(record["Channel"], record["EventID"]) for record in short}
    for pair in {
        ("Security", 4624),
        ("Security", 4625),
        ("Microsoft-Windows-Sysmon/Operational", 1),
        ("Security", 4698),
        ("Microsoft-Windows-TaskScheduler/Operational", 106),
        ("Microsoft-Windows-Sysmon/Operational", 12),
        ("Microsoft-Windows-Sysmon/Operational", 13),
        ("Microsoft-Windows-PowerShell/Operational", 4104),
        ("Microsoft-Windows-PowerShell/Operational", 4103),
        ("Windows PowerShell", 800),
        ("Microsoft-Windows-Sysmon/Operational", 10),
        ("Security", 4697),
        ("System", 7045),
        ("Microsoft-Windows-Sysmon/Operational", 11),
    }:
        assert pair in pairs


def test_relative_out_resolves_inside_the_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    monkeypatch.chdir(repo_root)
    out_name = "data/benign/_test_tmp_relative_out.zip"
    out_path = repo_root / out_name
    try:
        assert (
            benign_main(
                ["--hosts", "1", "--hours", "1", "--seed", "7", "--out", out_name]
            )
            == 0
        )
        assert out_path.is_file()
    finally:
        out_path.unlink(missing_ok=True)
    assert benign_main(["--hosts", "1", "--out", "/tmp/nope.zip"]) == 2


def test_every_record_normalizes_with_no_unknown_or_unmapped() -> None:
    records = generate(seed=7, hosts=4, hours=24)
    assert len(records) > 0
    unmapped: dict[tuple[str, int], int] = {}
    unknown = 0
    mapped = 0
    for lineno, record in enumerate(records, start=1):
        try:
            _normalize_record(record, lineno)
        except UnmappedEvent as exc:
            unmapped[exc.key] = unmapped.get(exc.key, 0) + 1
        except ValueError, TypeError, AttributeError:
            unknown += 1
        else:
            mapped += 1
    assert mapped == len(records), f"unmapped={unmapped} unknown={unknown}"
    assert unmapped == {}
    assert unknown == 0


def test_generated_events_pass_conformance() -> None:
    records = generate(seed=7, hosts=2, hours=6)
    failures = []
    for lineno, record in enumerate(records, start=1):
        event = _normalize_record(record, lineno)
        errors = check_record(json.loads(serialize_ocsf(event)))
        if errors:
            failures.append("\n".join(errors))
    assert failures == []


def test_bundle_streams_through_iter_dataset_file(tmp_path: Path) -> None:
    out = tmp_path / bundle_name(hosts=2, hours=6, seed=7)
    records = generate(seed=7, hosts=2, hours=6)
    write_bundle(records, out)
    stats = WindowsReadStats()
    events = list(iter_dataset_file(out, dataset_rel="benign-test", stats=stats))
    assert len(events) == len(records)
    assert stats.unmapped == {}
    assert stats.unsupported == 0
