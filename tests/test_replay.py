"""Tests for the replay loader, provenance isolation and leak freedom.

The loader normalizes raw dataset files into Parquet; the provenance
table (read here only as the eval harness would) joins events to
ground-truth keys. Adapter return values must never carry dataset
paths, file names or technique ids.
"""

import json
import zipfile
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from corvus.adapters.replay import format_summary, load_path
from corvus.adapters.replay.adapter import ReplayAdapter
from corvus.adapters.replay.schema import provenance_dir
from corvus.adapters.siem import Cursor, Entity
from corvus.normalize.technique_ids import find_technique_ids
from tests.fixtures import windows_events as fx

TECHNIQUE_ARCHIVE = "T1003_credprobe_fixture.zip"


def _write_zip(path: Path, lines: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("events.json", "\n".join(lines) + "\n")
    return path


def _five_raw_lines() -> list[str]:
    """Five raw flat records across classes, carrying no technique ids."""
    records = [
        fx.flat_sysmon_process(),
        fx.flat_sysmon_network(),
        fx.flat_sysmon_file(),
        fx.flat_security_logon(success=True),
        fx.flat_security_task(),
    ]
    return [json.dumps(record) for record in records]


def _load_five(tmp_path: Path) -> tuple[Path, ReplayAdapter]:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    archive = _write_zip(
        tmp_path / "data" / "atomic-windows-test.zip", _five_raw_lines()
    )
    replay_dir = tmp_path / "replay"
    summary = load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.files_loaded == 1
    assert summary.events_total == 5
    return replay_dir, ReplayAdapter(replay_dir)


def _provenance_rows(replay_dir: Path) -> list[dict[str, object]]:
    table = pq.read_table(provenance_dir(replay_dir))
    return table.to_pylist()


def test_load_five_raw_fixtures_then_query_by_entity_and_window(
    tmp_path: Path,
) -> None:
    replay_dir, adapter = _load_five(tmp_path)
    assert replay_dir.is_dir()
    assert len(adapter.query_events()) == 5
    assert len(adapter.query_events(Entity(host="web01"))) == 3
    assert len(adapter.query_events(Entity(host="db01"))) == 2
    assert len(adapter.query_events(Entity(ip="198.51.100.23"))) == 1
    windowed = adapter.query_events(start=fx.SYS_MS, end=fx.SYS_MS)
    assert len(windowed) == 5
    assert adapter.query_events(start=fx.SYS_MS + 1) == []
    page, cursor = adapter.stream_alerts(page_size=2)
    assert len(page) == 2
    assert isinstance(cursor, Cursor)
    rest, _ = adapter.stream_alerts(since=cursor, page_size=10)
    assert len(rest) == 3


def test_provenance_rows_cover_every_event_and_join_ground_truth_keys(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    archive = _write_zip(data_dir / TECHNIQUE_ARCHIVE, _five_raw_lines())
    replay_dir = tmp_path / "replay"
    load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    adapter = ReplayAdapter(replay_dir)
    event_uids = {event.metadata.uid for event in adapter.query_events()}
    rows = _provenance_rows(replay_dir)
    assert {row["uid"] for row in rows} == event_uids
    assert len(rows) == 5
    rel = f"{TECHNIQUE_ARCHIVE}"
    assert {row["file"] for row in rows} == {rel}
    # The harness joins provenance files to ground-truth keys: emulate it
    # with a synthetic ground-truth mapping over the same data dir.
    ground_truth = {
        rel: {"dataset": "security-datasets", "techniques": ["T1003"], "tactics": []}
    }
    (data_dir / "ground_truth.json").write_text(json.dumps(ground_truth))
    keys = set(json.loads((data_dir / "ground_truth.json").read_text()))
    assert all(row["file"] in keys for row in rows)
    assert all(row["in_band_technique_id"] is False for row in rows)


def test_provenance_flag_set_for_in_band_technique_id(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    record = fx.flat_sysmon_process()
    record["CommandLine"] = r"C:\AtomicRedTeam\atomics\T1218.005\payload.ps1"
    record["EventIdx"] = 500
    archive = _write_zip(data_dir / "clean-name.zip", [json.dumps(record)])
    replay_dir = tmp_path / "replay"
    summary = load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.in_band_events == 1
    assert summary.in_band_files == 1
    rows = _provenance_rows(replay_dir)
    assert len(rows) == 1
    assert rows[0]["in_band_technique_id"] is True
    # The evidence itself stays verbatim in the returned record.
    (event,) = ReplayAdapter(replay_dir).query_events()
    assert event.process is not None
    assert event.process.cmd_line == r"C:\AtomicRedTeam\atomics\T1218.005\payload.ps1"


def test_adapter_returns_never_leak_paths_or_technique_ids(
    tmp_path: Path,
) -> None:
    """Ground-truth isolation: file names carrying ids stay out of returns."""
    data_dir = tmp_path / "data"
    nested = data_dir / "datasets" / "atomic" / "windows"
    nested.mkdir(parents=True)
    archive = _write_zip(nested / TECHNIQUE_ARCHIVE, _five_raw_lines())
    replay_dir = tmp_path / "replay"
    load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    adapter = ReplayAdapter(replay_dir)
    dumps: list[str] = []
    page: list[object] = []
    since: Cursor | None = None
    while True:
        batch, since = adapter.stream_alerts(since=since, page_size=2)
        if not batch:
            break
        page.extend(batch)
    assert len(page) == 5
    dumps.extend(event.model_dump_json() for event in page)  # type: ignore[union-attr]
    dumps.extend(event.model_dump_json() for event in adapter.query_events())
    for entry in adapter.describe_sources().sources:
        dumps.append(entry.model_dump_json())
    for dump in dumps:
        assert "T1003" not in dump
        assert "credprobe" not in dump
        assert "datasets/atomic/windows" not in dump
        assert find_technique_ids(dump) == []


def test_load_summary_reports_counts(tmp_path: Path, capsys: object) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    archive = _write_zip(data_dir / "atomic-windows-test.zip", _five_raw_lines())
    replay_dir = tmp_path / "replay"
    summary = load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.per_class == {1007: 1, 4001: 1, 1001: 1, 3002: 1, 1006: 1}
    assert summary.unmapped == {}
    assert summary.unsupported == 0
    text = format_summary(summary, replay_dir)
    print(text)
    assert "5 total" in text
    assert "in-band technique ids: 0 events in 0 files" in text
    out = capsys.readouterr().out  # type: ignore[union-attr]
    assert "5 total" in out


def test_load_empty_store_queries_return_empty(tmp_path: Path) -> None:
    adapter = ReplayAdapter(tmp_path / "replay")
    assert adapter.query_events() == []
    page, _ = adapter.stream_alerts()
    assert page == []
    assert adapter.describe_sources().sources == []


def test_load_unsupported_file_suffix_loads_nothing(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "notes.txt").write_text("not a dataset file")
    replay_dir = tmp_path / "replay"
    summary = load_path(data_dir, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.files_loaded == 0
    assert summary.events_total == 0
    with pytest.raises(ValueError, match="unsupported"):
        load_path(data_dir / "notes.txt", replay_dir=replay_dir, data_dir=data_dir)


def test_load_missing_path_raises_instead_of_loading_zero(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    replay_dir = tmp_path / "replay"
    missing = data_dir / "no-such-file.zip"
    with pytest.raises(ValueError, match="does not exist"):
        load_path(missing, replay_dir=replay_dir, data_dir=data_dir)
    with pytest.raises(ValueError, match="does not exist"):
        load_path(tmp_path / "no-such-dir", replay_dir=replay_dir, data_dir=data_dir)


def test_cli_load_missing_path_exits_nonzero(tmp_path: Path, capsys: object) -> None:
    from corvus.cli import main as cli_main

    missing = tmp_path / "no-such-file.zip"
    with pytest.raises(SystemExit) as exc:
        cli_main(
            [
                "replay",
                "load",
                str(missing),
                "--replay-dir",
                str(tmp_path / "replay"),
                "--data-dir",
                str(tmp_path / "data"),
            ]
        )
    assert exc.value.code != 0
    assert "does not exist" in capsys.readouterr().err


def _write_small_json(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                json.dumps(fx.flat_sysmon_process()),
                json.dumps(fx.winlog_sysmon_file()),
            ]
        )
        + "\n"
    )
    return path


def test_bare_json_lines_file_loads_when_named_explicitly(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    small = _write_small_json(data_dir / "events.json")
    replay_dir = tmp_path / "replay"
    summary = load_path(small, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.files_loaded == 1
    assert summary.events_total == 2
    assert summary.files_empty == 0
    adapter = ReplayAdapter(replay_dir)
    assert len(adapter.query_events()) == 2
    assert len(adapter.query_events(Entity(host="web01"))) == 1
    assert len(adapter.query_events(Entity(host="db01"))) == 1


def test_empty_json_yields_nothing_and_counts_empty(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    empty = data_dir / "empty.json"
    empty.write_text("")
    replay_dir = tmp_path / "replay"
    summary = load_path(empty, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.files_loaded == 1
    assert summary.events_total == 0
    assert summary.files_empty == 1
    assert ReplayAdapter(replay_dir).query_events() == []


def test_directory_discovery_skips_bare_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _write_small_json(data_dir / "events.json")
    _write_zip(data_dir / "archive.zip", _five_raw_lines())
    replay_dir = tmp_path / "replay"
    summary = load_path(data_dir, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.files_loaded == 1
    assert summary.events_total == 5
    assert len(ReplayAdapter(replay_dir).query_events()) == 5


def test_data_relative_rejects_files_outside_data_dir(tmp_path: Path) -> None:
    from corvus.adapters.replay.loader import data_relative

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    outside = tmp_path / "elsewhere.zip"
    outside.write_text("not under the root")
    with pytest.raises(ValueError, match="outside the dataset root"):
        data_relative(outside, data_dir)
    with pytest.raises(ValueError, match="outside the dataset root"):
        load_path(outside, replay_dir=tmp_path / "replay", data_dir=data_dir)
    nested = data_dir / "sub" / "f.zip"
    nested.parent.mkdir(parents=True)
    nested.write_text("x")
    assert data_relative(nested, data_dir) == "sub/f.zip"


def test_interrupted_load_leaves_no_truncated_parquet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import corvus.adapters.replay.loader as loader_mod
    from corvus.adapters.replay.schema import events_dir, provenance_dir, slug_for_rel
    from corvus.normalize.windows import read_dataset_file

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    good = _write_zip(data_dir / "good.zip", _five_raw_lines())
    bad = _write_zip(data_dir / "bad.zip", _five_raw_lines())
    replay_dir = tmp_path / "replay"
    load_path(good, replay_dir=replay_dir, data_dir=data_dir)
    assert len(ReplayAdapter(replay_dir).query_events()) == 5

    staged = read_dataset_file(bad, dataset_rel="bad.zip").events

    def _flaky(path: Path, *, dataset_rel: str | None = None, stats: object = None):
        yield staged[0]
        yield staged[1]
        raise RuntimeError("boom mid-stream")

    monkeypatch.setattr(loader_mod, "iter_dataset_file", _flaky)
    with pytest.raises(RuntimeError, match="boom"):
        load_path(bad, replay_dir=replay_dir, data_dir=data_dir)
    slug = slug_for_rel("bad.zip")
    assert not (events_dir(replay_dir) / f"{slug}.parquet").exists()
    assert not (events_dir(replay_dir) / f"{slug}.parquet.tmp").exists()
    assert not (provenance_dir(replay_dir) / f"{slug}.parquet.tmp").exists()
    assert len(list(events_dir(replay_dir).glob("*.parquet"))) == 1
    assert len(ReplayAdapter(replay_dir).query_events()) == 5
