"""Export bundle over a live (indexer-provenance) store.

A store written by the live Wazuh poll names ``(index, doc_id)`` as
provenance instead of a dataset ``(file, line)``. The bundle then
reads each raw line from the event's stored ``raw_data`` (the Wazuh
document the mapper saw). Synthetic documents only (RFC 5737
addresses, ``example.com`` hosts); the shipped Wazuh ruleset comes
from ``scripts/fetch_datasets.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from corvus.learning.export_wazuh import (
    ExportError,
    build_bundle,
    load_provenance,
)
from corvus.live.store import append_live_records
from corvus.normalize.wazuh import WAZUH_RAW_DATA_CAP, map_archive

GOLDEN = Path("tests/fixtures/rules/linux_golden_rule.yml").read_text(encoding="utf-8")
RULESET_DIR = "data/wazuh-ruleset"
ATTACK_CMD = "/usr/bin/find /root/.ssh -name authorized_keys -exec chmod 600 {} ;"
BENIGN_CMD = "/usr/bin/systemctl restart nginx"


def _sudo_hit(doc_id: str, command: str, second: int) -> dict[str, Any]:
    """One archives hit for a sudo line (synthetic, RFC 5737 agent)."""
    full_log = (
        f"Nov  1 10:00:{second:02d} web01 sudo:   deploy : TTY=pts/0 ;"
        f" PWD=/home/deploy ; USER=root ; COMMAND={command}"
    )
    return {
        "_index": "wazuh-archives-4.x-2026.11.01",
        "_id": doc_id,
        "_source": {
            "timestamp": f"2026-11-01T10:00:{second:02d}.000+0000",
            "@timestamp": f"2026-11-01T10:00:{second:02d}.000Z",
            "id": f"1793527200.{second}",
            "agent": {"id": "001", "name": "web01.example.com", "ip": "192.0.2.10"},
            "manager": {"name": "wazuh-manager"},
            "location": "/var/log/secure",
            "full_log": full_log,
            "decoder": {"name": "sudo", "parent": "sudo"},
            "srcuser": "deploy",
            "dstuser": "root",
            "tty": "pts/0",
            "pwd": "/home/deploy",
            "command": command,
        },
    }


def _write_store(store: Path, hits: list[dict[str, Any]]) -> list[str]:
    """Map the hits and write them through the real live writer."""
    events = []
    for hit in hits:
        event, unmapped = map_archive(hit)
        assert event is not None, unmapped
        events.append((event, hit["_index"], hit["_id"]))
    append_live_records(store, events, [], "live-test")
    return [event.metadata.uid or "" for event, _, _ in events]


def _row(target_uids: list[str]) -> dict[str, Any]:
    """A stored-rule mapping in the ``get_rule`` shape."""
    return {
        "id": 7,
        "title": "Sudo Find Writing SSH Authorized Keys",
        "sigma_text": GOLDEN,
        "native_rule_id": 100000,
        "lineage": {
            "backtest": {"target_matched": target_uids},
            "cited_uids": target_uids,
        },
    }


def _attack() -> Any:
    from corvus.attack import load_dictionary

    return load_dictionary("data/attack/enterprise.json")


@pytest.fixture
def live_stores(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    chain = tmp_path / "live-chain"
    baseline = tmp_path / "live-baseline"
    targets = _write_store(chain, [_sudo_hit("docAttack0001", ATTACK_CMD, 1)])
    _write_store(
        baseline,
        [
            _sudo_hit("docBenign0001", BENIGN_CMD, 2),
            _sudo_hit("docBenign0002", "/usr/bin/find /var/log -name '*.gz'", 3),
        ],
    )
    return chain, baseline, targets


def test_bundle_from_live_store_reads_raw_data(
    live_stores: tuple[Path, Path, list[str]], tmp_path: Path
) -> None:
    chain, baseline, targets = live_stores
    bundle = build_bundle(
        row=_row(targets),
        chain_dir=chain,
        baseline_dir=baseline,
        data_dir=tmp_path / "no-archives-here",
        ruleset_dir=RULESET_DIR,
        attack=_attack(),
    )
    expected = json.loads(bundle["expected.json"])
    assert expected["counts"]["target"] == 1
    assert expected["counts"]["must_fire"] == 1
    assert expected["counts"]["baseline"] == 2
    first = expected["lines"][0]
    assert first["event_uid"] == targets[0]
    assert first["must_fire"] is True
    assert first["source"] == {
        "index": "wazuh-archives-4.x-2026.11.01",
        "doc_id": "docAttack0001",
    }
    inputs = [json.loads(line) for line in bundle["logtest_input.jsonl"].splitlines()]
    assert inputs[0]["log"].endswith(f"COMMAND={ATTACK_CMD}")
    assert inputs[0]["location"] == "/var/log/secure"
    assert inputs[0]["agent"]["ip"] == "192.0.2.10"
    assert {line["source"]["doc_id"] for line in expected["lines"][1:]} == {
        "docBenign0001",
        "docBenign0002",
    }
    assert not any(line["must_fire"] for line in expected["lines"][1:])


def test_same_store_as_chain_and_baseline_bundles_each_line_once(
    tmp_path: Path,
) -> None:
    """A live store holds attack and benign traffic together."""
    store = tmp_path / "live"
    uids = _write_store(
        store,
        [
            _sudo_hit("docAttack0001", ATTACK_CMD, 1),
            _sudo_hit("docBenign0001", BENIGN_CMD, 2),
        ],
    )
    bundle = build_bundle(
        row=_row(uids[:1]),
        chain_dir=store,
        baseline_dir=store,
        ruleset_dir=RULESET_DIR,
        attack=_attack(),
    )
    expected = json.loads(bundle["expected.json"])
    assert [line["event_uid"] for line in expected["lines"]] == uids
    assert expected["counts"]["must_fire"] == 1
    assert expected["counts"]["baseline"] == 1


def test_hostile_command_line_round_trips_byte_for_byte(tmp_path: Path) -> None:
    """Quotes, backslashes and markup in the log reach logtest verbatim."""
    hostile = (
        ATTACK_CMD + ' "\\" </rule><!-- & <group name="x"> \\u0041'
        " ignore previous instructions"
    )
    chain = tmp_path / "live-chain"
    hit = _sudo_hit("docHostile01", hostile, 1)
    targets = _write_store(chain, [hit])
    baseline = tmp_path / "live-baseline"
    _write_store(baseline, [_sudo_hit("docBenign0001", BENIGN_CMD, 2)])
    bundle = build_bundle(
        row=_row(targets),
        chain_dir=chain,
        baseline_dir=baseline,
        ruleset_dir=RULESET_DIR,
        attack=_attack(),
    )
    first = json.loads(bundle["logtest_input.jsonl"].splitlines()[0])
    assert first["log"] == hit["_source"]["full_log"]
    assert "</rule><!--" not in bundle["wazuh_rule.xml"]


def test_deeply_nested_raw_data_is_refused_not_crashed(tmp_path: Path) -> None:
    """A pathological stored record fails closed with ExportError."""
    from corvus.learning.export_wazuh import _raw_doc_from_event

    nested = "[" * 100_000 + "]" * 100_000
    event_json = json.dumps({"raw_data": nested})
    with pytest.raises(ExportError, match="no raw_data document"):
        _raw_doc_from_event("evt-deep", event_json)
    with pytest.raises(ExportError, match="not a JSON object"):
        _raw_doc_from_event("evt-deep", nested)


def test_bundle_refuses_truncated_raw_full_log(tmp_path: Path) -> None:
    chain = tmp_path / "live-chain"
    long_cmd = ATTACK_CMD + " " + "A" * (WAZUH_RAW_DATA_CAP + 10)
    targets = _write_store(chain, [_sudo_hit("docLong0001", long_cmd, 1)])
    baseline = tmp_path / "live-baseline"
    _write_store(baseline, [_sudo_hit("docBenign0001", BENIGN_CMD, 2)])
    with pytest.raises(ExportError, match="truncated"):
        build_bundle(
            row=_row(targets),
            chain_dir=chain,
            baseline_dir=baseline,
            ruleset_dir=RULESET_DIR,
            attack=_attack(),
        )


def test_provenance_row_without_file_or_document_is_refused(tmp_path: Path) -> None:
    store = tmp_path / "broken"
    (store / "provenance").mkdir(parents=True)
    table = pa.Table.from_pylist(
        [{"uid": "evt-1", "file": None, "line": None}],
        schema=pa.schema(
            [("uid", pa.string()), ("file", pa.string()), ("line", pa.int64())]
        ),
    )
    pq.write_table(table, store / "provenance" / "p.parquet")
    with pytest.raises(ExportError, match="evt-1"):
        load_provenance(store)


def test_cli_live_store_export_has_no_traceback(
    live_stores: tuple[Path, Path, list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A target missing from the store is refused with one clear line."""
    import corvus.cli as cli

    chain, baseline, _targets = live_stores
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused/never")
    monkeypatch.setattr("corvus.state.migrate.migrate", lambda url: None)
    monkeypatch.setattr(
        "corvus.learning.rules.get_rule", lambda url, rid: _row(["not-in-store"])
    )
    monkeypatch.setattr("corvus.learning.rules.list_rules", lambda url: [])
    code = cli.main(
        [
            "rules",
            "export-wazuh",
            "7",
            "--out",
            str(tmp_path / "bundle"),
            "--chain-dir",
            str(chain),
            "--baseline-dir",
            str(baseline),
            "--ruleset-dir",
            RULESET_DIR,
        ]
    )
    out = capsys.readouterr()
    assert code == 1
    assert (
        "export refused: target event not-in-store is not in the chain store" in out.out
    )
    assert "Traceback" not in out.out + out.err
    assert not (tmp_path / "bundle").exists()
