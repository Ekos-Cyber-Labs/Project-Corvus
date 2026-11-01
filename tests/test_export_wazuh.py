"""Export bundle + logtest parity tests (offline; stand-in runner).

The bundle is built from a real stored rule over the real Linux
stores; the wazuh-logtest transport is always a stand-in here (a
canned-answers file or a fake runner), never a server.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import psycopg
import pytest
import yaml

from corvus.learning.backtest import backtest
from corvus.learning.export_wazuh import ExportError, build_bundle, write_bundle
from corvus.learning.logtest import (
    LogtestError,
    LogtestVerdict,
    SubprocessLogtestRunner,
    compare_parity,
    parse_logtest_result,
)
from corvus.learning.rules import add_candidate, get_rule, list_rules
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls

FIXTURES = Path("tests/fixtures")
GOLDEN = (FIXTURES / "rules" / "linux_golden_rule.yml").read_text(encoding="utf-8")

GOLDEN_UIDS = [
    "lnx-d7bea80358fc93ab",
    "lnx-f749ba60b31e41e4",
    "lnx-22e99900825434c9",
]


@pytest.fixture
def export_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _store_golden(database_url: str) -> dict[str, Any]:
    result = backtest(GOLDEN, {"event_uids": GOLDEN_UIDS})
    assert result.accepted, result.codes
    return add_candidate(
        database_url, GOLDEN, None, GOLDEN_UIDS, result, "probe", "0.1"
    )


def _attack():
    from corvus.attack import load_dictionary

    return load_dictionary("data/attack/enterprise.json")


# Bundle ----------------------------------------------------------------


@pytest.mark.integration
def test_export_bundle_golden(export_db: str, tmp_path: Path) -> None:
    row = _store_golden(export_db)
    store_ids = [r["native_rule_id"] for r in list_rules(export_db)]
    bundle = build_bundle(row=row, store_ids=store_ids, attack=_attack())
    out = write_bundle(bundle, tmp_path / "bundle")
    assert sorted(p.name for p in out.iterdir()) == sorted(
        ["deploy_plan.txt", "expected.json", "logtest_input.jsonl", "wazuh_rule.xml"]
    )
    root = ET.fromstring((out / "wazuh_rule.xml").read_text(encoding="utf-8"))
    assert len(root.findall("rule")) == 2
    expected = json.loads((out / "expected.json").read_text(encoding="utf-8"))
    assert expected["rule_db_id"] == row["id"]
    assert expected["sigma_rule_id"] == row["lineage"]["sigma_rule_id"]
    assert expected["native_rule_ids"][0] == row["native_rule_id"]
    # Shadow levels follow the replaced parents, per source.
    assert expected["levels"] == {"sudo": 5, "auditd": 3}
    assert expected["parents"]["sudo"] == [5400, 5401, 5402, 5407, 5403, 5405, 5406]
    assert expected["parents"]["auditd"] == [80700, 80780, 80783, 80786, 80789, 80792]
    sudo_rule, audit_rule = root.findall("rule")
    assert sudo_rule.get("level") == "5"
    assert audit_rule.get("level") == "3"
    assert expected["counts"]["target"] >= 3
    assert expected["counts"]["must_fire"] >= 3
    assert expected["counts"]["baseline"] >= 1
    must = {line["event_uid"] for line in expected["lines"] if line["must_fire"]}
    assert {
        "lnx-d7bea80358fc93ab",
        "lnx-f749ba60b31e41e4",
        "lnx-6aada96a96a3c468",
    } <= must
    inputs = [
        json.loads(line)
        for line in (out / "logtest_input.jsonl").read_text().splitlines()
    ]
    assert len(inputs) == expected["counts"]["inputs"]
    for record in inputs:
        assert set(record) >= {"key", "location", "agent", "log"}
        assert isinstance(record["log"], str) and record["log"]
    plan = (out / "deploy_plan.txt").read_text(encoding="utf-8")
    for needle in (
        "wazuh-analysisd -t",
        "systemctl restart wazuh-manager",
        "local_rules.xml",
        "unchanged in count and",
        "now carrying the corvus_shadow group",
        "corvus_shadow",
        "Active note",
        "replaces the parent's alert with its own",
        "one JSON object per stdin line",
        "one JSON object per stdout line",
        "decoder block",
        "rule block",
        "CORVUS_WAZUH_LOGTEST_CMD",
        "sudo if_sid: 5400, 5401, 5402, 5407, 5403, 5405, 5406",
        "Rollback",
    ):
        assert needle in plan
    assert "ssh " not in plan and "10." not in plan  # no manager address


@pytest.mark.integration
def test_export_refuses_edited_text_and_writes_nothing(
    export_db: str, tmp_path: Path
) -> None:
    row = _store_golden(export_db)
    broken = yaml.safe_load(row["sigma_text"])
    broken["logsource"] = {"product": "windows", "category": "process_creation"}
    edited = yaml.safe_dump(broken, sort_keys=False, allow_unicode=True)
    with psycopg.connect(export_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE rules SET sigma_text = %s WHERE id = %s",
                (edited, row["id"]),
            )
        conn.commit()
    edited_row = get_rule(export_db, row["id"])
    assert edited_row is not None
    out = tmp_path / "bundle"
    with pytest.raises(ExportError):
        build_bundle(row=edited_row, store_ids=[row["native_rule_id"]])
    assert not out.exists()


@pytest.mark.integration
def test_write_bundle_refuses_nonempty_dir(export_db: str, tmp_path: Path) -> None:
    row = _store_golden(export_db)
    bundle = build_bundle(row=row, store_ids=[row["native_rule_id"]])
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "existing.txt").write_text("operator file", encoding="utf-8")
    with pytest.raises(ExportError):
        write_bundle(bundle, out)
    assert (out / "existing.txt").read_text(encoding="utf-8") == "operator file"
    assert not (out / "wazuh_rule.xml").exists()


# Logtest parsing -----------------------------------------------------------


def test_parse_logtest_result_shapes() -> None:
    fired = parse_logtest_result(
        {
            "decoder": {"name": "sudo"},
            "rule": {"id": "100000", "level": 2, "description": "x"},
        },
        rule_ids={100000, 100001},
    )
    assert fired == LogtestVerdict(fired=True, decoder="sudo", rule_id=100000, level=2)
    other = parse_logtest_result(
        {"decoder": {"name": "auditd"}, "rule": {"id": 5402, "level": 3}},
        rule_ids={100000, 100001},
    )
    assert other.fired is False and other.rule_id == 5402
    quiet = parse_logtest_result({"decoder": {"name": "auditd"}}, rule_ids={100000})
    assert quiet.fired is False and quiet.rule_id is None


@pytest.mark.parametrize(
    "raw",
    [
        [],
        "decoder",
        {},
        {"decoder": "sudo"},
        {"decoder": {}},
        {"decoder": {"name": "sudo"}, "rule": {"id": "abc"}},
        {"decoder": {"name": "sudo"}, "rule": {"id": None}},
        {"decoder": {"name": "sudo"}, "rule": []},
    ],
)
def test_parse_logtest_result_fails_closed(raw: Any) -> None:
    with pytest.raises(LogtestError):
        parse_logtest_result(raw, rule_ids={100000})


def test_compare_parity_lists_disagreements() -> None:
    expected = [
        {"key": 0, "event_uid": "u0", "must_fire": True},
        {"key": 1, "event_uid": "u1", "must_fire": False},
        {"key": 2, "event_uid": "u2", "must_fire": False},
    ]
    verdicts = [
        LogtestVerdict(fired=True, decoder="sudo", rule_id=1, level=2),
        LogtestVerdict(fired=False, decoder="sudo", rule_id=None, level=None),
        LogtestVerdict(fired=True, decoder="auditd", rule_id=9, level=2),
    ]
    report = compare_parity(expected, verdicts)
    assert report.agreement == 2
    assert [line.key for line in report.disagreements] == [2]
    assert report.to_dict()["disagreements"][0]["must_fire"] is False


def test_compare_parity_rejects_length_mismatch() -> None:
    with pytest.raises(LogtestError):
        compare_parity([{"key": 0}], [])


# Runner --------------------------------------------------------------------


def test_subprocess_runner_needs_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CORVUS_WAZUH_LOGTEST_CMD", raising=False)
    with pytest.raises(LogtestError):
        SubprocessLogtestRunner()


def test_subprocess_runner_garbage_fails_closed() -> None:
    runner = SubprocessLogtestRunner(command=["printf", "not json\\n"])
    with pytest.raises(LogtestError):
        runner.run([{"log": "x"}])


def test_subprocess_runner_count_mismatch() -> None:
    runner = SubprocessLogtestRunner(
        command=["printf", '{"decoder": {"name": "sudo"}}\\n']
    )
    with pytest.raises(LogtestError):
        runner.run([{"log": "a"}, {"log": "b"}])


def test_subprocess_runner_timeout() -> None:
    runner = SubprocessLogtestRunner(command=["sleep", "5"])
    with pytest.raises(LogtestError):
        runner.run([{"log": "x"}], timeout_s=0.2)


def test_subprocess_runner_nonzero_exit() -> None:
    runner = SubprocessLogtestRunner(command=["sh", "-c", "exit 3"])
    with pytest.raises(LogtestError):
        runner.run([{"log": "x"}])


def test_subprocess_runner_happy_path() -> None:
    runner = SubprocessLogtestRunner(
        command=["printf", '{"decoder": {"name": "sudo"}}\\n']
    )
    assert runner.run([{"log": "x"}]) == [{"decoder": {"name": "sudo"}}]


# CLI -----------------------------------------------------------------------


@pytest.mark.integration
def test_cli_export_and_logtest_agree(
    export_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from corvus.cli import main

    _store_golden(export_db)
    monkeypatch.setenv("DATABASE_URL", export_db)
    out = tmp_path / "bundle"
    assert (
        main(["rules", "export-wazuh", "1", "--out", str(out), "--mode", "shadow"]) == 0
    )
    expected = json.loads((out / "expected.json").read_text(encoding="utf-8"))
    native = expected["native_rule_ids"]
    answers = tmp_path / "answers.jsonl"
    with answers.open("w", encoding="utf-8") as handle:
        for line in expected["lines"]:
            decoder = line["decoder"]
            if line["must_fire"]:
                rule_id = native[0] if decoder == "sudo" else native[1]
                handle.write(
                    json.dumps(
                        {
                            "decoder": {"name": decoder},
                            "rule": {"id": rule_id, "level": 2},
                        }
                    )
                    + "\n"
                )
            else:
                handle.write(json.dumps({"decoder": {"name": decoder}}) + "\n")
    monkeypatch.setenv("CORVUS_WAZUH_LOGTEST_CMD", f"cat {answers}")
    report_path = tmp_path / "parity.json"
    assert (
        main(
            [
                "rules",
                "logtest",
                "1",
                "--bundle",
                str(out),
                "--out",
                str(report_path),
            ]
        )
        == 0
    )
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["agreement"] == payload["inputs"] == expected["counts"]["inputs"]
    assert payload["disagreements"] == []
    bridge = payload["bridge"]
    assert "one JSON object per stdin line" in bridge["in"]
    assert "decoder block" in bridge["out"] and "rule block" in bridge["out"]
    assert "CORVUS_WAZUH_LOGTEST_CMD" in bridge["command"]


@pytest.mark.integration
def test_cli_logtest_garbage_answers_fails(
    export_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from corvus.cli import main

    _store_golden(export_db)
    monkeypatch.setenv("DATABASE_URL", export_db)
    out = tmp_path / "bundle"
    assert main(["rules", "export-wazuh", "1", "--out", str(out)]) == 0
    answers = tmp_path / "answers.jsonl"
    answers.write_text("this is not json\n", encoding="utf-8")
    monkeypatch.setenv("CORVUS_WAZUH_LOGTEST_CMD", f"cat {answers}")
    assert (
        main(
            [
                "rules",
                "logtest",
                "1",
                "--bundle",
                str(out),
                "--out",
                str(tmp_path / "p.json"),
            ]
        )
        != 0
    )
    assert not (tmp_path / "p.json").exists()
