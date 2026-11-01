"""Rule-store lifecycle tests (always run; never skip).

Postgres-backed via the shared guard: a missing or wrong database
fails, never skips. The passing backtest verdicts come from the real
Linux stores (see ``tests/test_backtest.py`` for the code pins).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import errors

from corvus.learning.backtest import backtest
from corvus.learning.rules import (
    add_candidate,
    archive_rule,
    get_rule,
    list_rules,
    roll_back_rule,
    transition_rule,
)
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls

FIXTURES = Path("tests/fixtures")
GOLDEN = (FIXTURES / "rules" / "linux_golden_rule.yml").read_text(encoding="utf-8")
BROAD = (FIXTURES / "rules" / "linux_golden_broad.yml").read_text(encoding="utf-8")

GOLDEN_UIDS = [
    "lnx-d7bea80358fc93ab",
    "lnx-f749ba60b31e41e4",
    "lnx-22e99900825434c9",
]

T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


@pytest.fixture
def rules_db() -> Any:
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def passing_verdict() -> Any:
    """The golden control's passing verdict on the real stores."""
    result = backtest(GOLDEN, {"event_uids": GOLDEN_UIDS})
    assert result.accepted, result.codes
    return result


def failing_verdict() -> Any:
    """The deliberately broad variant's rejection."""
    result = backtest(BROAD, {"event_uids": GOLDEN_UIDS})
    assert not result.accepted
    return result


def rule_count(test_url: str) -> int:
    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM rules")
            row = cur.fetchone()
    assert row is not None
    return int(row[0])


# Lifecycle ---------------------------------------------------------------


@pytest.mark.integration
def test_add_candidate_forces_experimental(rules_db: str) -> None:
    import uuid as uuid_module

    import yaml

    row = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.1", T0
    )
    assert row["status"] == "candidate"
    assert row["lineage"]["version"] == 1
    assert row["native_rule_id"] == 100000
    stored_id = row["lineage"]["sigma_rule_id"]
    # The model's id is ignored: Corvus assigns a fresh uuid4, so the
    # stored id is a valid UUID that is not the model's look-alike.
    assert stored_id != "7c4f3a21-9b6e-4f2a-8c1d-3e5f6a7b8c9d"
    assert uuid_module.UUID(stored_id).version == 4
    stored_doc = yaml.safe_load(row["sigma_text"])
    assert stored_doc["id"] == stored_id
    # The stored text agrees with the pre-promotion lifecycle: the
    # Sigma status is experimental while the row status is candidate.
    assert stored_doc["status"] == "experimental"
    assert row["lineage"]["producer"] == "probe"
    assert row["lineage"]["cited_uids"] == GOLDEN_UIDS
    assert row["lineage"]["backtest"]["codes"] == ["accepted"]
    assert row["created_at"] == T0
    assert get_rule(rules_db, row["id"]) == row


@pytest.mark.integration
def test_same_submission_twice_gets_distinct_ids(rules_db: str) -> None:
    first = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.1", T0
    )
    second = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.2", T0
    )
    # Each store assigns a fresh id, so re-storing one submission can
    # never bump another rule's version: two rows, distinct Sigma
    # ids, each version 1, the old row untouched.
    assert first["lineage"]["sigma_rule_id"] != second["lineage"]["sigma_rule_id"]
    assert first["version"] == 1
    assert second["version"] == 1
    assert second["native_rule_id"] == 100001
    assert get_rule(rules_db, first["id"])["status"] == "candidate"
    assert get_rule(rules_db, first["id"])["lineage"]["version"] == 1


@pytest.mark.integration
def test_proposal_reusing_stored_id_gets_fresh_id(rules_db: str) -> None:
    import yaml

    from corvus.learning.backtest import backtest

    first = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.1", T0
    )
    stored_id = first["lineage"]["sigma_rule_id"]
    # A proposal reusing the stored rule's id (the collision the live
    # review found): same accepted detection shape would still pass,
    # so forge the id onto an equivalent submission and backtest it.
    forged = yaml.safe_load(GOLDEN)
    forged["id"] = stored_id
    forged_text = yaml.safe_dump(forged, sort_keys=False, allow_unicode=True)
    verdict = backtest(forged_text, {"event_uids": GOLDEN_UIDS})
    assert verdict.accepted, verdict.codes
    second = add_candidate(
        rules_db, forged_text, None, GOLDEN_UIDS, verdict, "probe", "0.2", T0
    )
    assert second["lineage"]["sigma_rule_id"] != stored_id
    assert second["version"] == 1
    # The rule whose id was reused keeps its version: no wrong bump.
    assert get_rule(rules_db, first["id"])["lineage"]["version"] == 1
    assert get_rule(rules_db, first["id"])["lineage"]["sigma_rule_id"] == stored_id


@pytest.mark.integration
def test_failed_verifier_cannot_be_stored(rules_db: str) -> None:
    with pytest.raises(ValueError):
        add_candidate(
            rules_db, BROAD, None, GOLDEN_UIDS, failing_verdict(), "probe", "0.1", T0
        )
    assert rule_count(rules_db) == 0


@pytest.mark.integration
def test_mismatched_backtest_result_rejected(rules_db: str) -> None:
    verdict = passing_verdict().to_dict()
    verdict["rule_id"] = "00000000-0000-4000-8000-000000000000"
    with pytest.raises(ValueError):
        add_candidate(rules_db, GOLDEN, None, GOLDEN_UIDS, verdict, "probe", "0.1", T0)
    assert rule_count(rules_db) == 0


@pytest.mark.integration
def test_experimental_text_still_evaluates_in_shadow(rules_db: str) -> None:
    import yaml

    from corvus.learning.shadow import compile_shadow_rules, shadow_rules

    row = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.1", T0
    )
    assert yaml.safe_load(row["sigma_text"])["status"] == "experimental"
    transition_rule(rules_db, row["id"], "shadow", approver="ana", reason="shadow soak")
    pairs, skipped = compile_shadow_rules(shadow_rules(rules_db))
    assert skipped == {}
    assert len(pairs) == 1
    assert pairs[0][0].rule_id == row["lineage"]["sigma_rule_id"]


@pytest.mark.integration
def test_transitions_need_approver_and_reason(rules_db: str) -> None:
    row = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.1", T0
    )
    with pytest.raises(ValueError):
        transition_rule(rules_db, row["id"], "shadow", approver="", reason="ok")
    with pytest.raises(ValueError):
        transition_rule(rules_db, row["id"], "shadow", approver="ana", reason="  ")
    with pytest.raises(ValueError):
        transition_rule(rules_db, row["id"], "active", approver="ana", reason="skip")
    shadow = transition_rule(
        rules_db, row["id"], "shadow", approver="ana", reason="backtest clean"
    )
    assert shadow["status"] == "shadow"
    assert shadow["deployed_at"] is not None
    history = shadow["lineage"]["history"]
    assert history[-1]["approver"] == "ana"
    assert history[-1]["reason"] == "backtest clean"
    active = transition_rule(
        rules_db, row["id"], "active", approver="ana", reason="soak ok"
    )
    assert active["status"] == "active"
    rolled = roll_back_rule(
        rules_db, row["id"], approver="ana", reason="fp in the wild"
    )
    assert rolled["status"] == "rolled_back"
    archived = archive_rule(rules_db, row["id"], approver="ana", reason="superseded")
    assert archived["status"] == "archived"
    with pytest.raises(ValueError):
        transition_rule(
            rules_db, row["id"], "shadow", approver="ana", reason="resurrect"
        )


@pytest.mark.integration
def test_list_orders_newest_first(rules_db: str) -> None:
    first = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.1", T0
    )
    second = add_candidate(
        rules_db, GOLDEN, None, GOLDEN_UIDS, passing_verdict(), "probe", "0.2", T0
    )
    assert [row["id"] for row in list_rules(rules_db)] == [second["id"], first["id"]]
    assert [row["id"] for row in list_rules(rules_db, status="candidate")] == [
        second["id"],
        first["id"],
    ]
    assert list_rules(rules_db, status="active") == []
    assert get_rule(rules_db, 999999) is None


@pytest.mark.integration
def test_native_id_range_and_race_refusal(rules_db: str) -> None:
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            None,
            GOLDEN_UIDS,
            passing_verdict(),
            "probe",
            "0.1",
            T0,
            native_rule_id=99999,
        )
    first = add_candidate(
        rules_db,
        GOLDEN,
        None,
        GOLDEN_UIDS,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
        native_rule_id=100005,
    )
    assert first["native_rule_id"] == 100005
    with pytest.raises(errors.UniqueViolation):
        add_candidate(
            rules_db,
            GOLDEN,
            None,
            GOLDEN_UIDS,
            passing_verdict(),
            "probe",
            "0.2",
            T0,
            native_rule_id=100005,
        )
    with psycopg.connect(rules_db) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM rules WHERE native_rule_id = 100005")
            row = cur.fetchone()
    assert row is not None and int(row[0]) == 1


# CLI ---------------------------------------------------------------------


@pytest.mark.integration
def test_cli_backtest_accepts_and_rejects(
    rules_db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from corvus.cli import main

    golden_file = tmp_path / "golden.yml"
    golden_file.write_text(GOLDEN, encoding="utf-8")
    broad_file = tmp_path / "broad.yml"
    broad_file.write_text(BROAD, encoding="utf-8")
    assert (
        main(
            [
                "rules",
                "backtest",
                str(golden_file),
                "--event-uid",
                GOLDEN_UIDS[0],
                "--event-uid",
                GOLDEN_UIDS[1],
            ]
        )
        == 0
    )
    assert "accepted" in capsys.readouterr().out
    assert (
        main(
            [
                "rules",
                "backtest",
                str(broad_file),
                "--event-uid",
                GOLDEN_UIDS[0],
            ]
        )
        == 1
    )
    assert "rejected" in capsys.readouterr().out


@pytest.mark.integration
def test_cli_add_list_show(
    rules_db: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from corvus.cli import main

    monkeypatch.setenv("DATABASE_URL", rules_db)
    golden_file = tmp_path / "golden.yml"
    golden_file.write_text(GOLDEN, encoding="utf-8")
    assert (
        main(
            [
                "rules",
                "add",
                str(golden_file),
                "--event-uid",
                GOLDEN_UIDS[0],
                "--event-uid",
                GOLDEN_UIDS[1],
                "--producer",
                "probe",
                "--producer-version",
                "0.1",
            ]
        )
        == 0
    )
    assert "stored candidate id=" in capsys.readouterr().out
    assert main(["rules", "list"]) == 0
    listed = capsys.readouterr().out
    assert "candidate" in listed
    # The model's id never reaches the store: list shows the assigned one.
    assert "7c4f3a21-9b6e-4f2a-8c1d-3e5f6a7b8c9d" not in listed
    assert main(["rules", "show", "1"]) == 0
    shown = capsys.readouterr().out
    assert "7c4f3a21-9b6e-4f2a-8c1d-3e5f6a7b8c9d" not in shown
    assert "experimental" in shown
