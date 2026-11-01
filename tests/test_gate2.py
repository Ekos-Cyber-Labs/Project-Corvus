"""Gate-2 evidence tests: failures first, synthetic stores, real shapes.

Every store here is built by the existing Linux loader from
hand-written archive lines that copy the real ``auditd`` SYSCALL
shapes (sanitized values, RFC 5737 IPs, fixed serials and epochs —
no wall clock, no dataset content). Alert files copy the real
Wazuh alert shape. Postgres-backed via the shared guard: a missing
or wrong database fails, never skips.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest

from corvus.adapters.replay.linux_loader import load_linux_path
from corvus.learning.backtest import backtest
from corvus.learning.rules import add_candidate
from corvus.state.migrate import migrate
from eval.gate2 import (
    GateInputError,
    in_window,
    main,
    parse_ground_truth,
    run_gate2,
)
from tests.conftest import _create_database, _drop_database, _test_database_urls

CANARY = "gate2canaryx"
FILLER = "plain"

#: Fixed epochs (ms): training day, variant day, far apart, no clock.
TRAIN_T = 1760000000000
VAR_T = 1761000000000
NEG_T = VAR_T + 3600000

RULE_TEXT = """title: Gate2 canary rule
id: 11111111-1111-4111-8111-111111111111
status: test
description: Synthetic stand-in for a learned rule (canary literal).
author: gate2 tests
date: 2026-10-20
logsource:
  product: linux
  category: process_creation
detection:
  sel_img:
    Image|endswith: '/find'
  sel_canary:
    CommandLine|contains: 'gate2canaryx'
  sel_exec:
    CommandLine|contains: '-exec'
  condition: sel_img and sel_canary and sel_exec
level: medium
"""


@pytest.fixture
def gate_db() -> Any:
    """Throwaway Postgres database with migrations applied."""
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def iso_ms(moment_ms: int) -> str:
    """Render epoch ms as a Wazuh-style stamp (``+0000``)."""
    return (
        datetime.fromtimestamp(moment_ms / 1000, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3]
        + "+0000"
    )


def audit_doc(serial: str, epoch_ms: int, argv: list[str], pid: str) -> dict[str, Any]:
    """One synthetic auditd SYSCALL doc (real shape, sanitized values)."""
    epoch = f"{epoch_ms / 1000:.3f}"
    args = " ".join(f'a{i}="{v}"' for i, v in enumerate(argv))
    proctitle = "".join(f"{ord(c):02X}00" for c in " ".join(argv))
    full_log = (
        f"type=SYSCALL msg=audit({epoch}:{serial}): arch=c000003e syscall=59 "
        "success=yes exit=0 a0=7fff00000000 a1=7fff00000000 a2=7fff00000000 "
        f"a3=8 items=2 ppid=1 pid={pid} auid=4294967295 uid=0 gid=0 euid=0 "
        "suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 "
        'comm="find" exe="/usr/bin/find" key="process_creation"'
        f"ARCH=x86_64 SYSCALL=execve type=EXECVE msg=audit({epoch}:{serial}): "
        f"argc={len(argv)} {args} type=CWD msg=audit({epoch}:{serial}): "
        'cwd="/" type=PATH msg=audit('
        f'{epoch}:{serial}): item=0 name="/usr/bin/find" mode=0100755 '
        "ouid=0 ogid=0 rdev=00:00 nametype=NORMAL "
        f"type=PROCTITLE msg=audit({epoch}:{serial}): proctitle={proctitle}"
    )
    return {
        "timestamp": iso_ms(epoch_ms),
        "agent": {"id": "001", "name": "synth-victim", "ip": "192.0.2.10"},
        "manager": {"name": "synth-wazuh"},
        "id": f"1.{serial}",
        "full_log": full_log,
        "decoder": {"parent": "auditd", "name": "auditd"},
        "data": {
            "audit": {
                "type": "SYSCALL",
                "id": serial,
                "syscall": "59",
                "success": "yes",
                "ppid": "1",
                "pid": pid,
                "auid": "4294967295",
                "uid": "0",
                "euid": "0",
                "command": "find",
                "exe": "/usr/bin/find",
                "key": "process_creation",
                "execve": {f"a{i}": v for i, v in enumerate(argv)},
                "cwd": "/",
                "file": {"name": "/usr/bin/find"},
            }
        },
        "location": "/var/log/audit/audit.log",
    }


def alert_line(
    moment_ms: int,
    rule_id: str,
    groups: list[str],
    level: int = 5,
    description: str = "synthetic alert",
) -> str:
    """One synthetic Wazuh alert line (real shape, sanitized values)."""
    return json.dumps(
        {
            "timestamp": iso_ms(moment_ms),
            "rule": {
                "level": level,
                "description": description,
                "id": rule_id,
                "firedtimes": 1,
                "mail": False,
                "groups": groups,
            },
            "agent": {"id": "001", "name": "synth-victim", "ip": "192.0.2.10"},
            "manager": {"name": "synth-wazuh"},
            "id": f"9{moment_ms}.0",
            "full_log": "synthetic",
            "decoder": {"parent": "sudo", "name": "sudo"},
            "location": "/var/log/auth.log",
        }
    )


def write_lines(path: Path, lines: list[str]) -> Path:
    """Write JSON-lines with a trailing newline; return the path."""
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_gt(path: Path, steps: list[dict[str, Any]]) -> Path:
    """Write a ground-truth JSON-lines file; return the path."""
    return write_lines(path, [json.dumps(step) for step in steps])


def gt_step(
    step: int,
    technique: str,
    start_ms: int,
    end_ms: int,
    expected: str = "detect",
    variant_specific: list[str] | None = None,
) -> dict[str, Any]:
    """One ground-truth line (ISO-8601 UTC)."""
    record: dict[str, Any] = {
        "chain": "synth",
        "step": step,
        "technique": technique,
        "start": iso_ms(start_ms).replace("+0000", "Z"),
        "end": iso_ms(end_ms).replace("+0000", "Z"),
        "expected": expected,
        "desc": "synthetic find behavior",
    }
    if variant_specific is not None:
        record["variant_specific"] = variant_specific
    return record


def load_store(archive_path: Path, store_dir: Path, data_root: Path) -> dict[str, int]:
    """Load one archive file; return the uid->time index."""
    summary = load_linux_path(archive_path, replay_dir=store_dir, data_dir=data_root)
    assert summary.events_total > 0
    from eval.gate2 import read_store_index

    index, _window = read_store_index(store_dir)
    return index


def canary_uid(serial: str) -> str:
    """The deterministic uid of a synthetic audit doc (dedupe hash)."""
    import hashlib

    return "lnx-" + hashlib.sha256(f"audit:001:{serial}".encode()).hexdigest()[:16]


def insert_attempt(
    db_url: str,
    created_ms: int,
    purpose: str = "rule_proposal",
    model: str = "synth-spark",
) -> int:
    """Insert one llm_attempts row at an explicit time; return its id."""
    created = datetime.fromtimestamp(created_ms / 1000, tz=UTC)
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO llm_attempts (call_id, model, purpose,"
                " attempt_number, outcome, created_at)"
                " VALUES (%s, %s, %s, 1, 'ok', %s) RETURNING id",
                ("gate2-test", model, purpose, created),
            )
            row = cur.fetchone()
        conn.commit()
    assert row is not None
    return int(row[0])


def insert_spend(db_url: str, created_ms: int, model: str = "synth-spark") -> None:
    """Insert one spend row at an explicit time."""
    created = datetime.fromtimestamp(created_ms / 1000, tz=UTC)
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO spend (model, tokens_in, tokens_out, usd,"
                " created_at) VALUES (%s, 10, 5, 0.000001, %s)",
                (model, created),
            )
        conn.commit()


def build_world(
    db_url: str,
    root: Path,
    *,
    rule_created_ms: int = VAR_T - 3600000,
    ledger_ids: str = "clean",
) -> dict[str, Any]:
    """Build the VALID-case world; return every handle the tests need.

    ``ledger_ids`` selects the rule lineage ledger content: ``"clean"``
    (two pre-variant attempts), ``"late"`` (plus one attempt inside
    the variant), ``"unknown"`` (plus a nonexistent id), ``"none"``
    (no ledger ids recorded).
    """
    data = root / "data"
    (data / "exports-train").mkdir(parents=True)
    (data / "exports-base").mkdir(parents=True)
    (data / "exports-pos").mkdir(parents=True)
    (data / "exports-neg").mkdir(parents=True)
    stores = root / "stores"
    gt_dir = root / "gt"
    gt_dir.mkdir(parents=True)

    train_docs = [
        audit_doc(
            "900001",
            TRAIN_T + 1000,
            ["/usr/bin/find", "/tmp", "-exec", CANARY],
            "101",
        ),
        audit_doc(
            "900002",
            TRAIN_T + 2000,
            ["/usr/bin/find", "/var", "-exec", CANARY],
            "102",
        ),
    ]
    for i in range(38):
        train_docs.append(
            audit_doc(
                f"911{i:03d}",
                TRAIN_T + 3000 + i,
                ["/usr/bin/find", "/usr", "-name", f"{FILLER}{i}"],
                f"21{i:03d}",
            )
        )
    train_archive = data / "exports-train" / "ossec-archive-train.json"
    write_lines(train_archive, [json.dumps(doc) for doc in train_docs])
    base_docs = [
        audit_doc(
            f"920{i:03d}",
            TRAIN_T + 9000 + i,
            ["/usr/bin/find", "/etc", "-name", f"benign{i}"],
            f"31{i:03d}",
        )
        for i in range(40)
    ]
    base_archive = data / "exports-base" / "ossec-archive-base.json"
    write_lines(base_archive, [json.dumps(doc) for doc in base_docs])
    train_store = stores / "train"
    base_store = stores / "base"
    load_store(train_archive, train_store, data)
    load_store(base_archive, base_store, data)
    targets = [canary_uid("900001"), canary_uid("900002")]

    verdict = backtest(
        RULE_TEXT,
        {"event_uids": targets},
        baseline_dir=base_store,
        chain_dir=train_store,
    )
    assert verdict.accepted, verdict.codes

    attempt_a = insert_attempt(db_url, VAR_T - 1800000)
    attempt_b = insert_attempt(db_url, VAR_T - 1700000)
    insert_spend(db_url, VAR_T - 1800000)
    if ledger_ids == "clean":
        lineage_ids: list[int] | None = [attempt_a, attempt_b]
    elif ledger_ids == "late":
        lineage_ids = [attempt_a, insert_attempt(db_url, VAR_T + 6000)]
    elif ledger_ids == "unknown":
        lineage_ids = [attempt_a, 999999999]
    else:
        lineage_ids = None
    extra = None
    if lineage_ids is not None:
        extra = {
            "rounds_used": 1,
            "model": "synth-spark",
            "prompt_version": "rule_proposal/v1",
            "ledger_ids": lineage_ids,
        }
    created = datetime.fromtimestamp(rule_created_ms / 1000, tz=UTC)
    rule = add_candidate(
        db_url,
        RULE_TEXT,
        None,
        targets,
        verdict,
        "gate2-tests",
        "v1",
        created,
        extra_lineage=extra,
    )
    sigma_id = rule["lineage"]["sigma_rule_id"]

    train_gt = gt_dir / "train.jsonl"
    write_gt(
        train_gt,
        [
            gt_step(1, "T1046", TRAIN_T, TRAIN_T + 1500),
            gt_step(2, "T1053.003", TRAIN_T + 1500, TRAIN_T + 4000),
        ],
    )

    pos_docs = [
        audit_doc(
            "950001", VAR_T + 1000, ["/usr/bin/find", "/tmp", "-name", "v1"], "501"
        ),
        audit_doc(
            "950002",
            VAR_T + 6000,
            ["/usr/bin/find", "/srv", "-exec", "varianttoolx"],
            "502",
        ),
        audit_doc(
            "950003", VAR_T + 12000, ["/usr/bin/find", "/opt", "-name", "v3"], "503"
        ),
    ]
    pos_dir = data / "exports-pos"
    write_lines(
        pos_dir / "ossec-archive-pos.json",
        [json.dumps(doc) for doc in pos_docs],
    )
    learned_at = VAR_T + 6500
    write_lines(
        pos_dir / "alerts-pos.json",
        [
            alert_line(VAR_T + 1500, "5502", ["pam", "syslog"]),
            alert_line(
                learned_at,
                str(rule["native_rule_id"]),
                [f"corvus_{sigma_id}", "corvus_shadow"],
                description="Gate2 canary rule",
            ),
        ],
    )
    pos_gt = gt_dir / "positive.jsonl"
    write_gt(
        pos_gt,
        [
            gt_step(1, "T1046", VAR_T, VAR_T + 4000, expected="miss"),
            gt_step(
                2,
                "T1053.003",
                VAR_T + 5000,
                VAR_T + 9000,
                variant_specific=["varianttoolx", "find"],
            ),
        ],
    )

    neg_docs = [
        audit_doc(
            "960001", NEG_T + 1000, ["/usr/bin/find", "/tmp", "-name", "w1"], "601"
        ),
        audit_doc(
            "960002", NEG_T + 6000, ["/usr/bin/find", "/srv", "-name", "w2"], "602"
        ),
    ]
    neg_dir = data / "exports-neg"
    write_lines(
        neg_dir / "ossec-archive-neg.json",
        [json.dumps(doc) for doc in neg_docs],
    )
    write_lines(
        neg_dir / "alerts-neg.json",
        [
            alert_line(NEG_T + 1500, "5502", ["pam", "syslog"]),
            alert_line(NEG_T + 6500, "5503", ["pam", "syslog"]),
        ],
    )
    neg_gt = gt_dir / "negative.jsonl"
    write_gt(
        neg_gt,
        [
            gt_step(1, "T1046", NEG_T, NEG_T + 4000, expected="miss"),
            gt_step(2, "T1053.003", NEG_T + 5000, NEG_T + 9000),
        ],
    )

    insert_attempt(db_url, learned_at + 60000, purpose="triage")
    insert_spend(db_url, learned_at + 60000)

    return {
        "data": data,
        "rule": rule,
        "sigma_id": sigma_id,
        "targets": targets,
        "train_store": train_store,
        "base_store": base_store,
        "train_gt": train_gt,
        "pos_dir": pos_dir,
        "pos_gt": pos_gt,
        "neg_dir": neg_dir,
        "neg_gt": neg_gt,
        "learned_at": learned_at,
        "out": root / "reports" / "gate2.md",
    }


def gate_kwargs(world: dict[str, Any], db_url: str, **over: Any) -> dict[str, Any]:
    """Default run_gate2 kwargs for the built world plus overrides."""
    kwargs: dict[str, Any] = {
        "database_url": db_url,
        "rule_id": int(world["rule"]["id"]),
        "train_gt": world["train_gt"],
        "positive": world["pos_dir"],
        "positive_gt": world["pos_gt"],
        "negative": world["neg_dir"],
        "negative_gt": world["neg_gt"],
        "baseline_dir": world["base_store"],
        "train_dir": world["train_store"],
        "data_dir": world["data"],
        "producing_command": "corvus eval gate2 (test)",
        "commit": "testcommit",
    }
    kwargs.update(over)
    return kwargs


# Pure unit tests (no database) -----------------------------------------


def test_unknown_expected_refuses(tmp_path: Path) -> None:
    """A ground-truth line with an unknown expected value refuses."""
    path = write_gt(
        tmp_path / "bad.jsonl",
        [
            {
                "step": 1,
                "technique": "T1046",
                "start": iso_ms(VAR_T).replace("+0000", "Z"),
                "end": iso_ms(VAR_T + 1000).replace("+0000", "Z"),
                "expected": "maybe",
            }
        ],
    )
    with pytest.raises(GateInputError, match="unknown expected value"):
        parse_ground_truth(path)


def test_duplicate_step_refuses(tmp_path: Path) -> None:
    """Two lines for the same step refuse (ambiguous windows)."""
    path = write_gt(
        tmp_path / "dup.jsonl",
        [
            gt_step(1, "T1046", VAR_T, VAR_T + 1000),
            gt_step(1, "T1046", VAR_T + 2000, VAR_T + 3000),
        ],
    )
    with pytest.raises(GateInputError, match="duplicate step"):
        parse_ground_truth(path)


def test_end_before_start_refuses(tmp_path: Path) -> None:
    """A step whose end precedes its start refuses."""
    path = write_gt(tmp_path / "bad.jsonl", [gt_step(1, "T1046", VAR_T + 1000, VAR_T)])
    with pytest.raises(GateInputError, match="end is before start"):
        parse_ground_truth(path)


def test_window_boundary_is_inclusive(tmp_path: Path) -> None:
    """Alerts exactly on the window edges count as in-window."""
    from eval.gate2 import AlertDoc, GtStep

    step = GtStep(
        step=1,
        technique="T1046",
        start_ms=1000,
        end_ms=2000,
        expected="detect",
        variant_specific=(),
        desc="",
    )
    for moment in (1000, 1500, 2000):
        alert = AlertDoc(
            time_ms=moment, rule_id="1", groups=(), level=3, description=""
        )
        assert in_window(alert, step)
    for moment in (999, 2001):
        alert = AlertDoc(
            time_ms=moment, rule_id="1", groups=(), level=3, description=""
        )
        assert not in_window(alert, step)


def test_malformed_alert_refuses(tmp_path: Path) -> None:
    """An alert line without a rule block refuses with its location."""
    from eval.gate2 import parse_alert_file

    path = write_lines(
        tmp_path / "alerts-bad.json",
        ['{"timestamp": "2026-10-20T00:00:01.000+0000", "rule": {}}'],
    )
    with pytest.raises(GateInputError, match="no rule id"):
        parse_alert_file(path)


def test_empty_export_dir_refuses(tmp_path: Path) -> None:
    """A directory with no Wazuh files refuses before loading anything."""
    from eval.gate2 import classify_export

    with pytest.raises(GateInputError, match="no Wazuh export files"):
        classify_export(tmp_path)


# Integration tests (Postgres-backed, never skip) ------------------------


@pytest.mark.integration
def test_valid_world_reports_valid(gate_db: str, tmp_path: Path) -> None:
    """The clean world is VALID with every section populated from data."""
    world = build_world(gate_db, tmp_path)
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "VALID", result.codes
    assert result.codes == []
    payload = result.payload
    assert all(row["result"] == "PASS" for row in payload["anti_leak"])
    pos_steps = {row["step"]: row for row in payload["positive"]["steps"]}
    assert pos_steps[2]["verdict"] == "PASS"
    assert pos_steps[2]["learned_n"] == 1
    assert pos_steps[2]["first_delay_s"] == 1.5
    assert pos_steps[2]["rule_db_id"] == int(world["rule"]["id"])
    assert pos_steps[2]["rule_version"] == 1
    assert pos_steps[2]["shipped"] == {}
    assert pos_steps[1]["verdict"] == "PASS"
    assert pos_steps[1]["shipped"] == {"5502": 1}
    assert payload["positive"]["false_positives"] == []
    assert payload["baseline"]["matches_n"] == 0
    assert payload["negative"]["learned_n"] == 0
    inside = payload["ledger"]["segments"]["inside"]
    assert inside["attempts"]["rows"] == 0
    assert inside["spend_rows"] == 0
    after = payload["ledger"]["segments"]["after"]
    assert after["attempts"]["rows"] == 1
    assert after["attempts"]["by_purpose_model"][0]["purpose"] == "triage"
    limits = payload["limits"]
    assert limits["expected_miss_missed"] == [1]
    assert limits["expected_detect_missed"] == []
    assert limits["uncovered_by_any_rule"] == []
    assert limits["distinct_learned_rules"]["n"] == 1
    assert limits["training_set"]["incidents_n"] == 0
    assert limits["training_set"]["cited_events_n"] == 2
    assert limits["behavior_same_as_training"] is True
    assert limits["variant_specific_declared_n"] == 2


@pytest.mark.integration
def test_rule_created_after_variant_start_is_invalid(
    gate_db: str, tmp_path: Path
) -> None:
    """A rule created 3 s after the first variant step is INVALID (a)."""
    world = build_world(gate_db, tmp_path, rule_created_ms=VAR_T + 3000)
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "rule_created_after_variant_start" in result.codes


@pytest.mark.integration
def test_variant_ground_truth_as_train_gt_is_invalid(
    gate_db: str, tmp_path: Path
) -> None:
    """Passing the variant ground truth as --train-gt is INVALID.

    The cited training events (fixed training-day epochs) fall outside
    every variant window, so the timestamp comparison fires.
    """
    world = build_world(gate_db, tmp_path)
    result = run_gate2(**gate_kwargs(world, gate_db, train_gt=world["pos_gt"]))
    assert result.verdict == "INVALID"
    assert result.codes == ["lineage_outside_training_windows"]


@pytest.mark.integration
def test_one_cited_event_outside_training_windows_is_invalid(
    gate_db: str, tmp_path: Path
) -> None:
    """One cited event outside the training windows fails the gate."""
    world = build_world(gate_db, tmp_path)
    write_gt(
        world["train_gt"],
        [
            gt_step(1, "T1046", TRAIN_T, TRAIN_T + 1000),
            gt_step(2, "T1053.003", TRAIN_T + 1001, TRAIN_T + 1500),
        ],
    )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "lineage_outside_training_windows" in result.codes
    row = next(
        item
        for item in result.payload["anti_leak"]
        if item["check"] == "b-lineage-in-training-windows"
    )
    assert row["result"] == "FAIL"
    assert canary_uid("900002") in row["outside_uids"]
    assert canary_uid("900001") not in row["outside_uids"]


@pytest.mark.integration
def test_unresolvable_cited_event_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """A cited uid missing from the training store is INVALID, never silent."""
    world = build_world(gate_db, tmp_path)
    partial_archive = world["data"] / "exports-partial.json"
    docs = [
        audit_doc(
            "900001",
            TRAIN_T + 1000,
            ["/usr/bin/find", "/tmp", "-exec", CANARY],
            "101",
        )
    ]
    for i in range(10):
        docs.append(
            audit_doc(
                f"941{i:03d}",
                TRAIN_T + 3000 + i,
                ["/usr/bin/find", "/usr", "-name", f"partial{i}"],
                f"51{i:03d}",
            )
        )
    write_lines(partial_archive, [json.dumps(doc) for doc in docs])
    partial_store = tmp_path / "stores" / "train-partial"
    load_store(partial_archive, partial_store, world["data"])
    result = run_gate2(**gate_kwargs(world, gate_db, train_dir=partial_store))
    assert result.verdict == "INVALID"
    assert result.codes == ["lineage_event_unresolved"]


@pytest.mark.integration
def test_cited_events_on_window_edges_pass(gate_db: str, tmp_path: Path) -> None:
    """Cited events exactly on a training window edge count as inside."""
    world = build_world(gate_db, tmp_path)
    write_gt(
        world["train_gt"],
        [gt_step(1, "T1046", TRAIN_T + 1000, TRAIN_T + 2000)],
    )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "VALID", result.codes
    row = next(
        item
        for item in result.payload["anti_leak"]
        if item["check"] == "b-lineage-in-training-windows"
    )
    assert row["result"] == "PASS"


@pytest.mark.integration
def test_cited_uid_in_variant_export_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """A training-cited uid reappearing in a variant export is INVALID (b)."""
    world = build_world(gate_db, tmp_path)
    archive = world["data"] / "exports-pos" / "ossec-archive-pos.json"
    with open(archive, "a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                audit_doc(
                    "900001",
                    VAR_T + 6000,
                    ["/usr/bin/find", "/tmp", "-exec", CANARY],
                    "505",
                )
            )
            + "\n"
        )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "lineage_uid_in_variant_export" in result.codes


@pytest.mark.integration
def test_variant_specific_value_in_rule_is_invalid(
    gate_db: str, tmp_path: Path
) -> None:
    """A variant-only value present in the detection text is INVALID (c)."""
    world = build_world(gate_db, tmp_path)
    write_gt(
        world["pos_gt"],
        [
            gt_step(1, "T1046", VAR_T, VAR_T + 4000, expected="miss"),
            gt_step(
                2,
                "T1053.003",
                VAR_T + 5000,
                VAR_T + 9000,
                variant_specific=[CANARY],
            ),
        ],
    )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "variant_specific_in_rule" in result.codes


@pytest.mark.integration
def test_late_ledger_id_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """A recorded attempt created inside the variant is INVALID (d)."""
    world = build_world(gate_db, tmp_path, ledger_ids="late")
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "ledger_after_variant_start" in result.codes


@pytest.mark.integration
def test_unknown_ledger_id_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """A recorded attempt id missing from llm_attempts is INVALID (d)."""
    world = build_world(gate_db, tmp_path, ledger_ids="unknown")
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "ledger_id_unknown" in result.codes


@pytest.mark.integration
def test_no_ledger_ids_stays_valid(gate_db: str, tmp_path: Path) -> None:
    """Non-model provenance (no ledger ids) passes check (d) with a note."""
    world = build_world(gate_db, tmp_path, ledger_ids="none")
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "VALID", result.codes
    check = next(
        row
        for row in result.payload["anti_leak"]
        if row["check"] == "d-model-never-saw-variant"
    )
    assert check["result"] == "PASS"
    assert "non-model provenance" in check["detail"]


@pytest.mark.integration
def test_negative_control_firing_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """Any learned-rule alert in the rule-absent export is INVALID."""
    world = build_world(gate_db, tmp_path)
    neg_alerts = world["data"] / "exports-neg" / "alerts-neg.json"
    with open(neg_alerts, "a", encoding="utf-8") as handle:
        handle.write(
            alert_line(
                NEG_T + 6500,
                str(world["rule"]["native_rule_id"]),
                [f"corvus_{world['sigma_id']}", "corvus_shadow"],
            )
            + "\n"
        )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "negative_control_fired" in result.codes
    assert "swapped_positive_negative" not in result.codes


@pytest.mark.integration
def test_swapped_exports_are_detected(gate_db: str, tmp_path: Path) -> None:
    """Learned findings only in the negative export means swapped dirs."""
    world = build_world(gate_db, tmp_path)
    pos_alerts = world["data"] / "exports-pos" / "alerts-pos.json"
    write_lines(pos_alerts, [alert_line(VAR_T + 1500, "5502", ["pam", "syslog"])])
    neg_alerts = world["data"] / "exports-neg" / "alerts-neg.json"
    with open(neg_alerts, "a", encoding="utf-8") as handle:
        handle.write(
            alert_line(
                NEG_T + 6500,
                str(world["rule"]["native_rule_id"]),
                [f"corvus_{world['sigma_id']}", "corvus_shadow"],
            )
            + "\n"
        )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "swapped_positive_negative" in result.codes
    assert "negative_control_fired" in result.codes


@pytest.mark.integration
def test_surprise_on_expected_miss_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """A detection on an expected-miss step is a surprise, never a pass."""
    world = build_world(gate_db, tmp_path)
    pos_alerts = world["data"] / "exports-pos" / "alerts-pos.json"
    with open(pos_alerts, "a", encoding="utf-8") as handle:
        handle.write(
            alert_line(
                VAR_T + 1500,
                str(world["rule"]["native_rule_id"]),
                [f"corvus_{world['sigma_id']}", "corvus_shadow"],
            )
            + "\n"
        )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "surprise_detect" in result.codes
    rows = {row["step"]: row for row in result.payload["positive"]["steps"]}
    assert rows[1]["verdict"] == "SURPRISE"


@pytest.mark.integration
def test_missed_expected_detect_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """An expected-detect step with no learned alert is a failure."""
    world = build_world(gate_db, tmp_path)
    pos_alerts = world["data"] / "exports-pos" / "alerts-pos.json"
    write_lines(pos_alerts, [alert_line(VAR_T + 1500, "5502", ["pam", "syslog"])])
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "missed_expected_detect" in result.codes
    assert "positive_no_learned_findings" in result.codes


@pytest.mark.integration
def test_false_positive_outside_windows_is_invalid(
    gate_db: str, tmp_path: Path
) -> None:
    """A learned alert outside every step window is INVALID."""
    world = build_world(gate_db, tmp_path)
    pos_alerts = world["data"] / "exports-pos" / "alerts-pos.json"
    with open(pos_alerts, "a", encoding="utf-8") as handle:
        handle.write(
            alert_line(
                VAR_T + 12000,
                str(world["rule"]["native_rule_id"]),
                [f"corvus_{world['sigma_id']}", "corvus_shadow"],
            )
            + "\n"
        )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "positive_false_positive" in result.codes
    assert len(result.payload["positive"]["false_positives"]) == 1


@pytest.mark.integration
def test_baseline_match_is_invalid(gate_db: str, tmp_path: Path) -> None:
    """The same rule firing on the baseline is INVALID."""
    world = build_world(gate_db, tmp_path)
    tainted = tmp_path / "stores" / "tainted-base"
    tainted_archive = world["data"] / "exports-tainted.json"
    docs = [
        audit_doc(
            "930001",
            TRAIN_T + 9500,
            ["/usr/bin/find", "/tmp", "-exec", CANARY],
            "401",
        )
    ]
    for i in range(10):
        docs.append(
            audit_doc(
                f"931{i:03d}",
                TRAIN_T + 9600 + i,
                ["/usr/bin/find", "/etc", "-name", f"tb{i}"],
                f"41{i:03d}",
            )
        )
    write_lines(tainted_archive, [json.dumps(doc) for doc in docs])
    load_store(tainted_archive, tainted, world["data"])
    result = run_gate2(**gate_kwargs(world, gate_db, baseline_dir=tainted))
    assert result.verdict == "INVALID"
    assert "baseline_match" in result.codes
    assert result.payload["baseline"]["matches_n"] == 1


@pytest.mark.integration
def test_ledger_rows_in_detection_window_are_invalid(
    gate_db: str, tmp_path: Path
) -> None:
    """Model spend between the first step and the last finding is INVALID.

    The row below lands exactly on the last finding: the window is
    inclusive, so boundary spend still counts.
    """
    world = build_world(gate_db, tmp_path)
    insert_attempt(gate_db, int(world["learned_at"]), purpose="analysis")
    insert_spend(gate_db, int(world["learned_at"]))
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "INVALID"
    assert "ledger_rows_in_detection_window" in result.codes
    inside = result.payload["ledger"]["segments"]["inside"]
    assert inside["attempts"]["rows"] == 1
    assert inside["spend_rows"] == 1


@pytest.mark.integration
def test_other_learned_rules_are_reported_not_hidden(
    gate_db: str, tmp_path: Path
) -> None:
    """A second learned rule firing stays VALID but shows up in limits."""
    world = build_world(gate_db, tmp_path)
    pos_alerts = world["data"] / "exports-pos" / "alerts-pos.json"
    with open(pos_alerts, "a", encoding="utf-8") as handle:
        handle.write(
            alert_line(
                VAR_T + 6000,
                "100007",
                ["corvus_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "corvus_shadow"],
            )
            + "\n"
        )
    result = run_gate2(**gate_kwargs(world, gate_db))
    assert result.verdict == "VALID", result.codes
    distinct = result.payload["limits"]["distinct_learned_rules"]
    assert distinct["n"] == 2
    assert distinct["other_ids"]


@pytest.mark.integration
def test_empty_export_is_refused(gate_db: str, tmp_path: Path) -> None:
    """An export directory with no Wazuh files refuses (exit 2 path)."""
    world = build_world(gate_db, tmp_path)
    empty = tmp_path / "empty-export"
    empty.mkdir()
    (empty / "notes.txt").write_text("nothing here\n", encoding="utf-8")
    with pytest.raises(GateInputError, match="no Wazuh export files"):
        run_gate2(**gate_kwargs(world, gate_db, positive=empty))


def _cli_args(world: dict[str, Any], root: Path, db_url: str) -> list[str]:
    """CLI args with paths relative to the world root (data-relative load)."""
    return [
        "--rule",
        str(world["rule"]["id"]),
        "--train-gt",
        str(Path(world["train_gt"]).relative_to(root)),
        "--positive",
        str(Path(world["pos_dir"]).relative_to(root)),
        "--positive-gt",
        str(Path(world["pos_gt"]).relative_to(root)),
        "--negative",
        str(Path(world["neg_dir"]).relative_to(root)),
        "--negative-gt",
        str(Path(world["neg_gt"]).relative_to(root)),
        "--baseline-dir",
        str(Path(world["base_store"]).relative_to(root)),
        "--train-dir",
        str(Path(world["train_store"]).relative_to(root)),
        "--out",
        str(Path(world["out"]).relative_to(root)),
        "--database-url",
        db_url,
    ]


@pytest.mark.integration
def test_cli_valid_writes_reports(
    gate_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``corvus eval gate2`` on the clean world exits 0 with md+json."""
    world = build_world(gate_db, tmp_path)
    monkeypatch.chdir(tmp_path)
    code = main(_cli_args(world, tmp_path, gate_db))
    assert code == 0
    text = world["out"].read_text(encoding="utf-8")
    assert text.startswith("# Gate 2 — learned-rule variant evidence: VALID")
    assert "Producing command:" in text
    assert "git commit" in text
    report = json.loads(world["out"].with_suffix(".json").read_text(encoding="utf-8"))
    assert report["meta"]["verdict"] == "VALID"
    assert report["meta"]["codes"] == []
    assert report["meta"]["producing_command"].startswith("corvus eval gate2")


@pytest.mark.integration
def test_cli_invalid_reports_invalid_on_top(
    gate_db: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``corvus eval gate2`` on a leaky world exits 1, INVALID on top."""
    world = build_world(gate_db, tmp_path, rule_created_ms=VAR_T + 3000)
    monkeypatch.chdir(tmp_path)
    code = main(_cli_args(world, tmp_path, gate_db))
    assert code == 1
    assert "INVALID" in capsys.readouterr().out
    text = world["out"].read_text(encoding="utf-8")
    assert text.startswith("# Gate 2 — learned-rule variant evidence: INVALID")


@pytest.mark.integration
def test_cli_unknown_expected_exits_two(
    gate_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``corvus eval gate2`` with an unknown expected value exits 2."""
    world = build_world(gate_db, tmp_path)
    write_gt(
        world["pos_gt"],
        [
            {
                "step": 1,
                "technique": "T1046",
                "start": iso_ms(VAR_T).replace("+0000", "Z"),
                "end": iso_ms(VAR_T + 1000).replace("+0000", "Z"),
                "expected": "sometimes",
            }
        ],
    )
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(_cli_args(world, tmp_path, gate_db))
    assert exc.value.code == 2
