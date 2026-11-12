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


@pytest.mark.lab_data
@pytest.mark.integration
def test_add_candidate_forces_experimental(rules_db: str) -> None:
    import uuid as uuid_module

    import yaml

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
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
    assert row["lineage"]["cited_uids"] == GOLDEN_MATCHED
    assert row["lineage"]["backtest"]["codes"] == ["accepted"]
    assert row["created_at"] == T0
    assert get_rule(rules_db, row["id"]) == row


@pytest.mark.lab_data
@pytest.mark.integration
def test_same_submission_twice_gets_distinct_ids(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    second = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.2",
        T0,
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


@pytest.mark.lab_data
@pytest.mark.integration
def test_proposal_reusing_stored_id_gets_fresh_id(rules_db: str) -> None:
    import yaml

    from corvus.learning.backtest import backtest

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
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
        rules_db,
        forged_text,
        incident_id,
        GOLDEN_MATCHED,
        verdict,
        "probe",
        "0.2",
        T0,
    )
    assert second["lineage"]["sigma_rule_id"] != stored_id
    assert second["version"] == 1
    # The rule whose id was reused keeps its version: no wrong bump.
    assert get_rule(rules_db, first["id"])["lineage"]["version"] == 1
    assert get_rule(rules_db, first["id"])["lineage"]["sigma_rule_id"] == stored_id


@pytest.mark.integration
def test_failed_verifier_cannot_be_stored(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            BROAD,
            incident_id,
            GOLDEN_UIDS,
            failing_verdict(),
            "probe",
            "0.1",
            T0,
        )
    assert rule_count(rules_db) == 0


@pytest.mark.lab_data
@pytest.mark.integration
def test_mismatched_caller_verdict_is_ignored(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    garbage = passing_verdict().to_dict()
    garbage["rule_id"] = "00000000-0000-4000-8000-000000000000"
    garbage["codes"] = ["baseline_match"]
    garbage["accepted"] = False
    garbage.pop("sigma_sha256", None)
    row = add_candidate(
        rules_db, GOLDEN, incident_id, GOLDEN_MATCHED, garbage, "probe", "0.1", T0
    )
    assert row["lineage"]["backtest"]["codes"] == ["accepted"]
    assert row["lineage"]["backtest"]["target_matched"] == sorted(GOLDEN_MATCHED)


@pytest.mark.lab_data
@pytest.mark.integration
def test_experimental_text_still_evaluates_in_shadow(rules_db: str) -> None:
    import yaml

    from corvus.learning.shadow import compile_shadow_rules, shadow_rules

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    assert yaml.safe_load(row["sigma_text"])["status"] == "experimental"
    transition_rule(rules_db, row["id"], "shadow", approver="ana", reason="shadow soak")
    pairs, skipped = compile_shadow_rules(shadow_rules(rules_db))
    assert skipped == {}
    assert len(pairs) == 1
    assert pairs[0][0].rule_id == row["lineage"]["sigma_rule_id"]


@pytest.mark.lab_data
@pytest.mark.integration
def test_transitions_need_approver_and_reason(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
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


@pytest.mark.lab_data
@pytest.mark.integration
def test_list_orders_newest_first(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    second = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.2",
        T0,
    )
    assert [row["id"] for row in list_rules(rules_db)] == [second["id"], first["id"]]
    assert [row["id"] for row in list_rules(rules_db, status="candidate")] == [
        second["id"],
        first["id"],
    ]
    assert list_rules(rules_db, status="active") == []
    assert get_rule(rules_db, 999999) is None


@pytest.mark.lab_data
@pytest.mark.integration
def test_native_id_range_and_race_refusal(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            incident_id,
            GOLDEN_MATCHED,
            passing_verdict(),
            "probe",
            "0.1",
            T0,
            native_rule_id=99999,
        )
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
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
            incident_id,
            GOLDEN_MATCHED,
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


# Verdict binding -----------------------------------------------------------


#: The golden control matches two of the three cited chain events; only
#: those two may appear as cited lineage once the store binds verdicts.
GOLDEN_MATCHED = [
    "lnx-d7bea80358fc93ab",
    "lnx-f749ba60b31e41e4",
]


@pytest.mark.lab_data
@pytest.mark.integration
def test_swapped_detection_text_rejected(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    verdict = passing_verdict()
    other = GOLDEN.replace("authorized_keys", "authorized_keys2")
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            other,
            incident_id,
            GOLDEN_MATCHED,
            verdict,
            "probe",
            "0.1",
            T0,
        )
    assert rule_count(rules_db) == 0


@pytest.mark.lab_data
@pytest.mark.integration
def test_cited_uid_outside_match_rejected(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            incident_id,
            GOLDEN_MATCHED + ["lnx-22e99900825434c9"],
            passing_verdict(),
            "probe",
            "0.1",
            T0,
        )
    assert rule_count(rules_db) == 0


@pytest.mark.lab_data
@pytest.mark.integration
def test_lineage_records_sigma_hash(rules_db: str) -> None:
    import hashlib

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    assert (
        row["lineage"]["backtest"]["sigma_sha256"]
        == hashlib.sha256(GOLDEN.encode("utf-8")).hexdigest()
    )


# Versioning ----------------------------------------------------------------


@pytest.mark.lab_data
@pytest.mark.integration
def test_supersede_bumps_version(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    assert first["version"] == 1
    assert first["lineage"]["version"] == 1
    second = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.2",
        T0,
        supersedes=first["id"],
    )
    assert second["lineage"]["sigma_rule_id"] == first["lineage"]["sigma_rule_id"]
    assert second["version"] == 2
    assert second["lineage"]["version"] == 2
    assert second["lineage"]["supersedes"] == first["id"]
    assert second["native_rule_id"] != first["native_rule_id"]
    kept = get_rule(rules_db, first["id"])
    assert kept is not None
    assert kept["version"] == 1
    assert kept["lineage"]["version"] == 1
    assert kept["status"] == "candidate"


@pytest.mark.lab_data
@pytest.mark.integration
def test_supersede_unknown_id_rejected(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            incident_id,
            GOLDEN_MATCHED,
            passing_verdict(),
            "probe",
            "0.1",
            T0,
            supersedes=999999,
        )
    assert rule_count(rules_db) == 0


# Concurrent transitions ----------------------------------------------------


@pytest.mark.lab_data
@pytest.mark.integration
def test_concurrent_transition_one_wins(rules_db: str) -> None:
    import threading

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    transition_rule(rules_db, row["id"], "shadow", approver="ana", reason="soak")
    barrier = threading.Barrier(2)
    outcomes: dict[str, tuple[str, Any]] = {}

    def move(name: str, to_status: str) -> None:
        barrier.wait(timeout=30)
        try:
            outcomes[name] = (
                "ok",
                transition_rule(
                    rules_db,
                    row["id"],
                    to_status,
                    approver="ana",
                    reason=name,
                    from_status="shadow",
                ),
            )
        except Exception as exc:
            outcomes[name] = ("error", exc)

    threads = [
        threading.Thread(target=move, args=("go-active", "active")),
        threading.Thread(target=move, args=("go-rolled", "rolled_back")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert outcomes.keys() == {"go-active", "go-rolled"}
    kinds = sorted(kind for kind, _ in outcomes.values())
    assert kinds == ["error", "ok"]
    loser_name = "go-active" if outcomes["go-active"][0] == "error" else "go-rolled"
    loser = outcomes[loser_name]
    assert isinstance(loser[1], ValueError)
    winner = next(value for value in outcomes.values() if value[0] == "ok")
    final = get_rule(rules_db, row["id"])
    assert final is not None
    assert final["status"] == winner[1]["status"]
    # No history entry lost: candidate, the shadow move, and the winner.
    history = final["lineage"]["history"]
    assert [entry["to"] for entry in history] == [
        "candidate",
        "shadow",
        winner[1]["status"],
    ]


# Approver allow-list -------------------------------------------------------


@pytest.mark.lab_data
@pytest.mark.integration
def test_approver_allow_list(rules_db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    monkeypatch.setenv("CORVUS_RULE_APPROVERS", "ana,bob")
    with pytest.raises(ValueError):
        transition_rule(rules_db, row["id"], "shadow", approver="mallory", reason="x")
    assert get_rule(rules_db, row["id"])["status"] == "candidate"  # type: ignore[index]
    moved = transition_rule(
        rules_db, row["id"], "shadow", approver="ana", reason="listed"
    )
    assert moved["status"] == "shadow"
    monkeypatch.delenv("CORVUS_RULE_APPROVERS")
    closed = transition_rule(
        rules_db, row["id"], "archived", approver="mallory", reason="unset allows"
    )
    assert closed["status"] == "archived"


# CLI ---------------------------------------------------------------------


@pytest.mark.lab_data
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


# Store-side verification --------------------------------------------------
#
# The store never trusts a caller-supplied verdict: every store re-runs
# the backtest itself on the exact submitted text against the source
# incident's stored events and the baseline, and refuses unless the
# fresh result is accepted with codes == ["accepted"].


def _seed_incident(test_url: str, uids: list[str]) -> int:
    """Insert one incident carrying ``uids``; return its id."""
    import json as json_module
    import time as time_module

    with psycopg.connect(test_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, entity_keys,"
                " techniques, event_uids, first_seen, last_seen,"
                " deterministic_score, severity_floor, severity_id,"
                " severity_factors) VALUES (%s, %s, %s, %s, %s,"
                " to_timestamp(%s), to_timestamp(%s), %s, %s, %s, %s)"
                " RETURNING id",
                (
                    f"corr-learn-{time_module.time_ns()}",
                    "chain1 candidate",
                    json_module.dumps({}),
                    json_module.dumps(["T1105"]),
                    json_module.dumps(uids),
                    1793420700,
                    1793420800,
                    4.0,
                    4,
                    4,
                    json_module.dumps({}),
                ),
            )
            row = cur.fetchone()
            assert row is not None
        conn.commit()
    return int(row[0])


@pytest.mark.lab_data
@pytest.mark.integration
def test_candidate_without_incident_is_refused(rules_db: str) -> None:
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            None,
            GOLDEN_MATCHED,
            passing_verdict(),
            "probe",
            "0.1",
            T0,
        )
    assert rule_count(rules_db) == 0


@pytest.mark.integration
def test_forged_self_hashed_verdict_with_invented_uids_rejected(
    rules_db: str,
) -> None:
    import hashlib

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    forged = {
        "accepted": True,
        "codes": ["accepted"],
        "rule_id": "7c4f3a21-9b6e-4f2a-8c1d-3e5f6a7b8c9d",
        "target_matched": ["lnx-invented-0001", "lnx-invented-0002"],
        "target_total": 2,
        "baseline_count": 0,
        "group": "linux/process_creation",
        "sigma_sha256": hashlib.sha256(GOLDEN.encode("utf-8")).hexdigest(),
    }
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            incident_id,
            ["lnx-invented-0001", "lnx-invented-0002"],
            forged,
            "probe",
            "0.1",
            T0,
        )
    assert rule_count(rules_db) == 0


@pytest.mark.lab_data
@pytest.mark.integration
def test_caller_verdict_is_informational_only(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    stale = passing_verdict().to_dict()
    stale["target_matched"] = []
    row = add_candidate(
        rules_db, GOLDEN, incident_id, GOLDEN_MATCHED, stale, "probe", "0.1", T0
    )
    assert row["lineage"]["backtest"]["target_matched"] == sorted(GOLDEN_MATCHED)
    assert row["lineage"]["backtest"]["codes"] == ["accepted"]


@pytest.mark.lab_data
@pytest.mark.integration
def test_two_texts_cannot_share_a_verdict(rules_db: str) -> None:
    import hashlib

    import yaml

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    golden_verdict = passing_verdict()
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            BROAD,
            incident_id,
            GOLDEN_UIDS,
            golden_verdict,
            "probe",
            "0.1",
            T0,
        )
    assert rule_count(rules_db) == 0
    mutant_doc = yaml.safe_load(GOLDEN)
    assert isinstance(mutant_doc, dict)
    mutant_doc["title"] = "Sudo Find Writing SSH Authorized Keys (retitled)"
    mutant = yaml.safe_dump(mutant_doc, sort_keys=False, allow_unicode=True)
    mutant_row = add_candidate(
        rules_db,
        mutant,
        incident_id,
        GOLDEN_MATCHED,
        golden_verdict,
        "probe",
        "0.1",
        T0,
    )
    assert (
        mutant_row["lineage"]["backtest"]["sigma_sha256"]
        == hashlib.sha256(mutant.encode("utf-8")).hexdigest()
    )
    assert (
        mutant_row["lineage"]["backtest"]["sigma_sha256"]
        != hashlib.sha256(GOLDEN.encode("utf-8")).hexdigest()
    )


# Versioning ----------------------------------------------------------------


@pytest.mark.lab_data
@pytest.mark.integration
def test_double_supersede_of_same_parent_fails(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    second = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.2",
        T0,
        supersedes=first["id"],
    )
    assert second["version"] == 2
    with pytest.raises(ValueError):
        add_candidate(
            rules_db,
            GOLDEN,
            incident_id,
            GOLDEN_MATCHED,
            passing_verdict(),
            "probe",
            "0.3",
            T0,
            supersedes=first["id"],
        )
    assert sorted(row["version"] for row in list_rules(rules_db)) == [1, 2]


@pytest.mark.lab_data
@pytest.mark.integration
def test_concurrent_supersede_of_same_parent_one_wins(rules_db: str) -> None:
    import threading

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    barrier = threading.Barrier(2)
    outcomes: dict[str, tuple[str, Any]] = {}

    def race_once(name: str) -> None:
        barrier.wait(timeout=60)
        try:
            outcomes[name] = (
                "ok",
                add_candidate(
                    rules_db,
                    GOLDEN,
                    incident_id,
                    GOLDEN_MATCHED,
                    passing_verdict(),
                    "probe",
                    name,
                    T0,
                    supersedes=first["id"],
                ),
            )
        except Exception as exc:
            outcomes[name] = ("error", exc)

    threads = [
        threading.Thread(target=race_once, args=(f"racer-{index}",))
        for index in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert sorted(kind for kind, _ in outcomes.values()) == ["error", "ok"]
    loser = next(value for value in outcomes.values() if value[0] == "error")
    assert isinstance(loser[1], ValueError)
    assert sorted(row["version"] for row in list_rules(rules_db)) == [1, 2]


@pytest.mark.lab_data
@pytest.mark.integration
def test_supersede_archived_or_stale_revision_fails(rules_db: str) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)

    def store(version_tag: str, parent: int | None) -> dict[str, Any]:
        return add_candidate(
            rules_db,
            GOLDEN,
            incident_id,
            GOLDEN_MATCHED,
            passing_verdict(),
            "probe",
            version_tag,
            T0,
            supersedes=parent,
        )

    first = store("0.1", None)
    second = store("0.2", first["id"])
    third = store("0.3", second["id"])
    assert third["version"] == 3
    with pytest.raises(ValueError):
        store("0.4-stale", first["id"])
    archive_rule(rules_db, third["id"], approver="ana", reason="superseded")
    with pytest.raises(ValueError):
        store("0.5-archived", third["id"])
    fourth = store("0.4", second["id"])
    assert fourth["version"] == 4
    assert fourth["lineage"]["sigma_rule_id"] == first["lineage"]["sigma_rule_id"]
    assert sorted(row["version"] for row in list_rules(rules_db)) == [1, 2, 3, 4]


# Attribution -----------------------------------------------------------------


@pytest.mark.lab_data
@pytest.mark.integration
def test_attribution_picks_latest_active_revision(rules_db: str) -> None:
    from corvus.live.poll import load_stored_rules

    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    first = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    sigma_id = first["lineage"]["sigma_rule_id"]
    second = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.2",
        T0,
        supersedes=first["id"],
    )
    transition_rule(
        rules_db, second["id"], "shadow", approver="ana", reason="shadow soak"
    )
    _, by_sigma = load_stored_rules(rules_db)
    assert by_sigma[sigma_id]["version"] == 2
    assert by_sigma[sigma_id]["status"] == "shadow"
    archive_rule(rules_db, second["id"], approver="ana", reason="soak done")
    _, by_sigma_after = load_stored_rules(rules_db)
    assert by_sigma_after[sigma_id]["version"] == 1


# Approver --------------------------------------------------------------------


@pytest.mark.lab_data
@pytest.mark.integration
def test_approver_recorded_stripped(
    rules_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
    row = add_candidate(
        rules_db,
        GOLDEN,
        incident_id,
        GOLDEN_MATCHED,
        passing_verdict(),
        "probe",
        "0.1",
        T0,
    )
    monkeypatch.setenv("CORVUS_RULE_APPROVERS", "ana")
    moved = transition_rule(
        rules_db, row["id"], "shadow", approver=" ana ", reason="shadow soak"
    )
    assert moved["lineage"]["history"][-1]["approver"] == "ana"
    with pytest.raises(ValueError):
        transition_rule(
            rules_db, moved["id"], "active", approver=" mallory ", reason="nope"
        )


@pytest.mark.lab_data
@pytest.mark.integration
def test_cli_add_list_show(
    rules_db: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from corvus.cli import main

    monkeypatch.setenv("DATABASE_URL", rules_db)
    incident_id = _seed_incident(rules_db, GOLDEN_UIDS)
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
                "--incident",
                str(incident_id),
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
