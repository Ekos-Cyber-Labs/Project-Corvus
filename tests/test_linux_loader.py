"""Tests for the Linux archive replay loader (real-record fixtures)."""

import gzip
import json
from pathlib import Path

import pyarrow.parquet as pq

from corvus.adapters.replay.linux_loader import (
    discover_linux_files,
    load_linux_path,
)
from corvus.normalize import wazuh

FIXTURES = Path(__file__).parent / "fixtures" / "linux"


def _archive_docs(*names: str) -> list[dict]:
    return [
        json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
        for name in names
    ]


def _write_gz(path: Path, docs: list[object]) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for doc in docs:
            handle.write(doc if isinstance(doc, str) else json.dumps(doc))
            handle.write("\n")


def test_load_reports_counts_and_provenance(tmp_path: Path) -> None:
    src = tmp_path / "archives"
    src.mkdir()
    docs = _archive_docs("pam_open", "pam_open_j", "auth", "exec_hex")
    _write_gz(src / "ossec-archive-28.json.gz", [*docs, "{truncated"])
    store = tmp_path / "store"
    summary = load_linux_path(src, replay_dir=store, data_dir=tmp_path)
    assert summary.files_loaded == 1 and summary.files_skipped == 0
    assert summary.malformed == 1
    # The journald twin collapses onto the auth.log event.
    assert summary.deduplicated == 1
    assert summary.events_total == 3
    assert summary.per_class == {3002: 2, 1007: 1}
    prov_files = list((store / "provenance").glob("*.parquet"))
    assert len(prov_files) == 1
    prov = pq.read_table(prov_files[0])
    assert prov.schema.names == [
        "uid",
        "file",
        "line",
        "sha256",
        "dataset",
        "in_band_technique_id",
    ]
    rows = prov.to_pylist()
    assert {row["line"] for row in rows} == {1, 3, 4}
    assert all(len(row["sha256"]) == 64 for row in rows)
    events = (
        pq.read_table(list((store / "events").glob("*.parquet"))[0], columns=["uid"])
        .column("uid")
        .to_pylist()
    )
    assert {row["uid"] for row in rows} == set(events)


def test_load_is_idempotent_and_resumable(tmp_path: Path) -> None:
    src = tmp_path / "archives"
    src.mkdir()
    _write_gz(src / "ossec-archive-28.json.gz", _archive_docs("auth", "conn"))
    store = tmp_path / "store"
    first = load_linux_path(src, replay_dir=store, data_dir=tmp_path)
    assert first.events_total == 2
    second = load_linux_path(src, replay_dir=store, data_dir=tmp_path)
    assert second.files_skipped == 1 and second.files_loaded == 0
    assert second.events_total == 0
    events = sum(
        pq.read_metadata(path).num_rows for path in (store / "events").glob("*.parquet")
    )
    assert events == 2
    # A damaged output is rewritten, never half-kept: drop the
    # manifest entry and reload; the uid set is unchanged.
    import json as _json

    manifest_path = store / "manifest.json"
    manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.clear()
    manifest_path.write_text(_json.dumps(manifest), encoding="utf-8")
    third = load_linux_path(src, replay_dir=store, data_dir=tmp_path)
    assert third.deduplicated == 2 and third.events_total == 0


def test_companions_merge_into_one_event(tmp_path: Path) -> None:
    import copy

    src = tmp_path / "archives"
    src.mkdir()
    full = _archive_docs("exec_hex")[0]
    head, _, tail = full["full_log"].partition("type=EXECVE")
    syscall_doc = copy.deepcopy(full)
    # The SYSCALL document alone carries no argv: only the joined
    # companion restores the full command line.
    del syscall_doc["data"]["audit"]["execve"]
    syscall_doc["full_log"] = head
    companion = copy.deepcopy(full)
    companion["data"]["audit"] = {"type": "EXECVE", "id": "134195"}
    companion["full_log"] = "type=EXECVE" + tail
    _write_gz(src / "ossec-archive-28.json.gz", [syscall_doc, companion])
    store = tmp_path / "store"
    summary = load_linux_path(src, replay_dir=store, data_dir=tmp_path)
    assert summary.merged == 1
    assert summary.events_total == 1
    assert summary.per_class.get(1007, 0) == 1
    rows = pq.read_table(
        list((store / "events").glob("*.parquet"))[0], columns=["event_json"]
    ).to_pylist()
    assert "netstat -tulpn" in rows[0]["event_json"]


def test_discover_rejects_outside_paths(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError):
        discover_linux_files(tmp_path / "missing")
    bad = tmp_path / "notes.txt"
    bad.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        discover_linux_files(bad)


def test_all_store_events_conform(tmp_path: Path) -> None:
    from pydantic import TypeAdapter

    from corvus.adapters.replay.schema import serialize_ocsf
    from corvus.normalize.conformance import check_record
    from corvus.normalize.ocsf import OcsfEvent

    src = tmp_path / "archives"
    src.mkdir()
    _write_gz(
        src / "ossec-archive-28.json.gz",
        _archive_docs(
            "pam_open",
            "auth",
            "disc",
            "su_rec",
            "sudo_rec",
            "exec_hex",
            "file_open",
            "conn",
            "uauth",
            "login",
            "ustart",
            "ucmd",
        ),
    )
    store = tmp_path / "store"
    load_linux_path(src, replay_dir=store, data_dir=tmp_path)
    adapter = TypeAdapter(OcsfEvent)
    for path in (store / "events").glob("*.parquet"):
        for row in pq.read_table(path, columns=["event_json"]).to_pylist():
            event = adapter.validate_json(row["event_json"])
            assert check_record(json.loads(serialize_ocsf(event))) == []


def test_detector_covers_mapped_linux_fields() -> None:
    from corvus.guardrails.injection import _iter_fields

    _finding, event, _key, _dedupe = wazuh.map_linux_doc(
        json.loads((FIXTURES / "exec_hex.json").read_text(encoding="utf-8"))
    )
    assert event is not None
    fields = dict(_iter_fields(event.model_dump(mode="json")))
    assert "process.cmd_line" in fields
    _finding, file_event, _key, _dedupe = wazuh.map_linux_doc(
        json.loads((FIXTURES / "file_open.json").read_text(encoding="utf-8"))
    )
    assert file_event is not None
    assert "file.path" in dict(_iter_fields(file_event.model_dump(mode="json")))
