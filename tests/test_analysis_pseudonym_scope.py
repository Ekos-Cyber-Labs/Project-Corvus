"""Incident-scoped pseudonyms for the analysis verdict.

No paid API calls: the transport entry is monkeypatched with scripted
attempts; every Postgres-backed case builds a throwaway database
through the shared guard in ``tests/conftest.py``.

Incidents are built from ``tests/fixtures/siem_events.py`` (real OCSF
shapes, RFC 5737 addresses, ``example.com`` hosts): incident A uses the
``web01`` events, incident B the ``db01`` file event. Loader rows are
derived from the fixture events themselves (flat columns plus the full
OCSF dump), never invented fields.
"""

from __future__ import annotations

import json
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from corvus.adapters.siem import FakeAdapter
from corvus.guardrails.pseudonymizer import Pseudonymizer
from corvus.llm.agent import (
    _analysis_scope_pseudonyms,
    _load_steps,
    run_analysis,
)
from corvus.llm.call import CallContext, validate_semantics
from corvus.llm.config import BackendConfig
from corvus.llm.price_book import ModelPrice
from corvus.llm.tools import incident_scope_pseudonyms
from corvus.llm.transport import Attempt, ToolCall
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls
from tests.fixtures.siem_events import make_siem_fixture_events

START_ISO = "2026-10-27T12:00:00Z"
END_ISO = "2026-10-27T13:00:00Z"

HOST_A = "web01.example.com"
USER_A = "EXAMPLE\\jdoe"
HOST_B = "db01.example.com"
USER_B = "EXAMPLE\\svc-backup"


@pytest.fixture
def scope_db() -> Any:
    """Throwaway Postgres with migrations applied (guarded, never skips)."""
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _cloud_backend(model: str = "stub-cloud") -> BackendConfig:
    """Cloud stub backend (billed) on loopback."""
    return BackendConfig(
        purpose="analysis",
        model=model,
        base_url="http://127.0.0.1:9/v1",
        trust="cloud",
        concurrency=4,
        requests_per_minute=30,
        max_input_tokens=1000,
        max_output_tokens=500,
        api_key="TEST-ONLY-KEY",  # gitleaks:allow
    )


def _zero_prices(*models: str) -> dict[str, ModelPrice]:
    """Zero-rate price rows for stub models."""
    return {
        name: ModelPrice(
            model=name,
            input_per_mtok=0.0,
            cached_input_per_mtok=0.0,
            output_per_mtok=0.0,
            source="test",
            date="2026-10-29",
        )
        for name in models
    }


def _egress_filter() -> Any:
    from corvus.guardrails.egress import EgressFilter

    return EgressFilter(["127.0.0.1:9"])


def _script_attempt(
    content: str | None,
    *,
    finish_reason: str | None = "stop",
    tool_calls: tuple[ToolCall, ...] = (),
) -> Attempt:
    """Build one scripted usage-counted attempt."""
    return Attempt(
        http_status=200,
        content=content,
        reasoning=None,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
        tool_call_errors=(),
        prompt_tokens=10,
        cached_tokens=0,
        reasoning_tokens=2,
        answer_tokens=5,
        overhead_tokens=0,
        token_source="usage",
        latency_ms=3,
        error=None,
        refusal=None,
    )


class _ScriptTransport:
    """Scripted transport: one Attempt per call."""

    def __init__(self, scripts: list[Any]) -> None:
        self._scripts = list(scripts)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, backend: Any, messages: Any, **kwargs: Any) -> Attempt:
        self.calls.append(
            {"backend": backend, "messages": list(messages), "kwargs": kwargs}
        )
        index = min(len(self.calls) - 1, len(self._scripts) - 1)
        script = self._scripts[index]
        assert isinstance(script, Attempt)
        return script


def _patch_transport(
    monkeypatch: pytest.MonkeyPatch, scripts: list[Any]
) -> _ScriptTransport:
    import corvus.llm.call as call_module

    stub = _ScriptTransport(scripts)
    monkeypatch.setattr(call_module.transport_module, "run_attempt", stub)
    return stub


def _tool_call(call_id: str, name: str, arguments: dict[str, Any]) -> ToolCall:
    raw = json.dumps(arguments, sort_keys=True)
    return ToolCall(
        call_id=call_id,
        name=name,
        arguments_raw=raw,
        arguments=json.loads(raw),
    )


def _row_from_event(event: Any) -> dict[str, Any]:
    """Loader row from a fixture OCSF event (real shape, no invented fields)."""
    data = event.model_dump(mode="json")
    device = data.get("device") or {}
    actor = data.get("actor") or {}
    actor_user = (actor.get("user") or {}).get("name")
    src = (data.get("src_endpoint") or {}).get("ip")
    dst = (data.get("dst_endpoint") or {}).get("ip")
    metadata = data.get("metadata") or {}
    return {
        "event_uid": metadata.get("uid"),
        "time": data.get("time"),
        "class_uid": data.get("class_uid"),
        "host": device.get("hostname"),
        "user": actor_user,
        "ip": device.get("ip"),
        "src_ip": src,
        "dst_ip": dst,
        "data": data,
    }


def _seed_incident(
    db: str,
    *,
    key: str,
    uids: tuple[str, ...],
) -> int:
    """Insert one incident row; return its id."""
    with psycopg.connect(db, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, severity_factors, techniques, event_uids)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    key,
                    f"incident {key}",
                    3,
                    3,
                    Jsonb({"factor_1_stage": {"score": 2, "why": "test"}}),
                    Jsonb(["T1059"]),
                    Jsonb(list(uids)),
                ),
            )
            row = cur.fetchone()
            assert row is not None
            return int(row[0])


def _seed_triage(
    db: str,
    incident_id: int,
    *,
    host: str,
    user: str,
    uids: tuple[str, ...],
) -> None:
    """Store a resolved triage condensed from the fixture entities."""
    condensed = {
        "summary": f"Account {user} logged on to {host} and ran a command",
        "entities": [
            {"type": "host", "value": host},
            {"type": "user", "value": user},
        ],
        "key_events": [
            {"event_uid": uid, "reason": "matters for the chain"} for uid in uids
        ],
        "timeline": [
            {
                "time": START_ISO,
                "event_uid": uids[0],
                "description": "first event of the chain",
            }
        ],
        "visibility_gaps": [],
        "uncertainties": [],
        "language": "en",
    }
    with psycopg.connect(db, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incident_analyses (incident_id, stage, status,"
                " payload, language, model, deterministic_floor)"
                " VALUES (%s, 'triage', 'resolved', %s, 'en', 'glimmer', 3)",
                (
                    incident_id,
                    Jsonb({"condensed": condensed, "model": "glimmer"}),
                ),
            )


def _pseudo(db: str, kind: str, raw: str) -> str:
    """Return the stable pseudonym for one entity (registers it)."""
    pseudo = Pseudonymizer(db).get_or_create(kind, raw)
    assert pseudo is not None
    return pseudo


def _verdict_with(
    *,
    uid: str,
    timeline: str,
    response: str,
    uncertainty: str,
) -> str:
    """Valid AnalysisVerdict JSON with caller-supplied free text."""
    return json.dumps(
        {
            "verdict": "true_positive",
            "severity_id": 3,
            "confidence": 0.81,
            "timeline": [
                {"time": START_ISO, "event_uid": uid, "description": timeline}
            ],
            "response_plan": [response],
            "visibility_gaps": [],
            "uncertainties": [uncertainty],
            "language": "en",
        }
    )


def _attempt_rows(db: str, incident_id: int) -> list[dict[str, Any]]:
    """llm_attempts rows for one incident, oldest first."""
    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT attempt_number, failed_validator, errors, outcome"
                " FROM llm_attempts WHERE incident_id = %s ORDER BY id ASC",
                (incident_id,),
            )
            return [
                {
                    "n": row[0],
                    "validator": row[1],
                    "errors": row[2],
                    "outcome": row[3],
                }
                for row in cur.fetchall()
            ]


def _run_analysis(
    db: str,
    incident_id: int,
    adapter: FakeAdapter,
    rows: list[dict[str, Any]],
    *,
    monkeypatch: pytest.MonkeyPatch,
    scripts: list[Any],
) -> tuple[Any, _ScriptTransport]:
    """Run the analysis loop with a scripted transport."""
    stub = _patch_transport(monkeypatch, scripts)
    outcome = run_analysis(
        incident_id,
        lang="en",
        database_url=db,
        adapter=adapter,
        evidence_loader=lambda _incident: list(rows),
        backend=_cloud_backend(),
        prices=_zero_prices("stub-cloud"),
        egress_filter=_egress_filter(),
    )
    return outcome, stub


def _events_by_uid() -> dict[str, Any]:
    """Fixture OCSF events keyed by metadata uid."""
    return {event.metadata.uid: event for event in make_siem_fixture_events()}


@pytest.mark.parametrize("field", ["timeline", "response_plan", "uncertainties"])
def test_cross_incident_pseudonym_rejected_in_each_field(
    scope_db: str, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    """Another incident's host/user pseudonym fails validator 3 per field.

    The bad first attempt names the other incident's pseudonyms in one
    free-text field; the retry with the incident's own pseudonyms
    resolves. The stored payload never holds the other's real values,
    and the retry error never echoes them.
    """
    db = scope_db
    by_uid = _events_by_uid()
    incident_a_uids = ("wazuh-1", "wazuh-3")
    incident_b_uids = ("wazuh-5",)
    adapter = FakeAdapter([by_uid[uid] for uid in incident_a_uids])
    rows_a = [_row_from_event(by_uid[uid]) for uid in incident_a_uids]
    incident_a = _seed_incident(db, key="scope-a", uids=incident_a_uids)
    _seed_triage(db, incident_a, host=HOST_A, user=USER_A, uids=incident_a_uids)
    incident_b = _seed_incident(db, key="scope-b", uids=incident_b_uids)
    _seed_triage(db, incident_b, host=HOST_B, user=USER_B, uids=incident_b_uids)
    host_a = _pseudo(db, "host", HOST_A)
    user_a = _pseudo(db, "user", USER_A)
    host_b = _pseudo(db, "host", HOST_B)
    user_b = _pseudo(db, "user", USER_B)
    assert host_a != host_b
    assert user_a != user_b
    own_timeline = f"The {host_a} host and the {user_a} account ran a command"
    own_response = f"Isolate the {host_a} host and reset the {user_a} account"
    own_uncertainty = f"The {host_a} host role and the {user_a} account scope"
    foreign_timeline = f"The {host_b} host and the {user_b} account ran a command"
    foreign_response = f"Isolate the {host_b} host and reset the {user_b} account"
    foreign_uncertainty = f"The {host_b} host role and the {user_b} account scope"
    if field == "timeline":
        bad = _verdict_with(
            uid=incident_a_uids[0],
            timeline=foreign_timeline,
            response=own_response,
            uncertainty=own_uncertainty,
        )
    elif field == "response_plan":
        bad = _verdict_with(
            uid=incident_a_uids[0],
            timeline=own_timeline,
            response=foreign_response,
            uncertainty=own_uncertainty,
        )
    else:
        bad = _verdict_with(
            uid=incident_a_uids[0],
            timeline=own_timeline,
            response=own_response,
            uncertainty=foreign_uncertainty,
        )
    good = _verdict_with(
        uid=incident_a_uids[0],
        timeline=own_timeline,
        response=own_response,
        uncertainty=own_uncertainty,
    )
    outcome, _stub = _run_analysis(
        db,
        incident_a,
        adapter,
        rows_a,
        monkeypatch=monkeypatch,
        scripts=[_script_attempt(bad), _script_attempt(good)],
    )
    assert outcome.status == "resolved"
    assert outcome.attempts == 2
    rows = _attempt_rows(db, incident_a)
    assert len(rows) == 2
    assert rows[0]["validator"] == "semantics"
    assert rows[0]["outcome"] == "invalid"
    codes = [str(item.get("code")) for item in (rows[0]["errors"] or [])]
    assert "invalid_pseudonym" in codes
    assert rows[1]["validator"] is None
    assert rows[1]["outcome"] == "ok"
    for item in rows[0]["errors"] or []:
        assert HOST_B not in str(item) and USER_B not in str(item)
    stored = json.dumps(outcome.payload, sort_keys=True, default=str)
    assert HOST_B not in stored and USER_B not in stored
    assert host_b not in stored and user_b not in stored


def test_own_and_tool_shown_pseudonym_pass(
    scope_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The incident's own pseudonym plus a tool-shown pivot both pass.

    The loader omits ``wazuh-4`` (its ``203.0.113.7`` destination is a
    genuine pivot from the fixture): the first turn shows it through
    ``get_events`` and the final verdict naming it resolves.
    """
    db = scope_db
    by_uid = _events_by_uid()
    loader_uids = ("wazuh-1", "wazuh-3")
    adapter_uids = ("wazuh-1", "wazuh-3", "wazuh-4")
    adapter = FakeAdapter([by_uid[uid] for uid in adapter_uids])
    rows = [_row_from_event(by_uid[uid]) for uid in loader_uids]
    incident_id = _seed_incident(db, key="scope-pivot", uids=loader_uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=loader_uids)
    host_a = _pseudo(db, "host", HOST_A)
    pivot_ip = _pseudo(db, "ip", "203.0.113.7")
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-p1",
                "get_events",
                {
                    "host": host_a,
                    "start": START_ISO,
                    "end": END_ISO,
                    "limit": 10,
                },
            ),
        ),
    )
    timeline = (
        f"The {host_a} host contacted the {pivot_ip} address and the logs show it"
    )
    response = f"Isolate the {host_a} host and block the {pivot_ip} address now"
    uncertainty = f"The {host_a} host role and the {pivot_ip} address scope need review"
    good = _verdict_with(
        uid=loader_uids[0],
        timeline=timeline,
        response=response,
        uncertainty=uncertainty,
    )
    outcome, _stub = _run_analysis(
        db,
        incident_id,
        adapter,
        rows,
        monkeypatch=monkeypatch,
        scripts=[first, _script_attempt(good)],
    )
    assert outcome.status == "resolved"
    assert outcome.attempts == 2
    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT shown_pseudonyms FROM agent_steps WHERE incident_id = %s"
                " ORDER BY step_number ASC",
                (incident_id,),
            )
            shown_rows = [list(row[0] or []) for row in cur.fetchall()]
    shown_union = {token for shown in shown_rows for token in shown}
    assert pivot_ip in shown_union


def test_attacker_shaped_token_does_not_enter_scope(scope_db: str) -> None:
    """A pseudonym-shaped attacker string never enters the verdict scope."""
    db = scope_db
    by_uid = _events_by_uid()
    loader_uids = ("wazuh-1", "wazuh-3")
    rows = [_row_from_event(by_uid[uid]) for uid in loader_uids]
    incident_id = _seed_incident(db, key="scope-attacker", uids=loader_uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=loader_uids)
    from corvus.llm.agent import _incident_entities
    from corvus.llm.schemas import CondensedIncident

    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM incident_analyses WHERE incident_id = %s"
                " AND stage = 'triage'",
                (incident_id,),
            )
            stored = cur.fetchone()
            assert stored is not None
            condensed = dict((stored[0] or {}).get("condensed") or {})
    CondensedIncident.model_validate(condensed)
    attacker_rows = list(rows)
    attacker_event = dict(attacker_rows[0])
    attacker_event["user"] = "HOST-9999"
    attacker_data = dict(attacker_event["data"])
    attacker_data["process"] = {"cmd_line": "run HOST-9999 now"}
    attacker_event["data"] = attacker_data
    entities = _incident_entities(attacker_rows + [attacker_event], condensed)
    scope = incident_scope_pseudonyms(db, entities, [])
    assert "HOST-9999" not in scope
    bad = _verdict_with(
        uid=loader_uids[0],
        timeline="The HOST-9999 host ran a command and the logs show it",
        response="Isolate the host and reset the account now",
        uncertainty="The host role needs review and the logs show it",
    )
    parsed = json.loads(bad)
    context = CallContext(
        event_uids=list(loader_uids),
        deterministic_floor=3,
        language="en",
        valid_techniques={"T1059"},
        valid_pseudonyms=scope,
        payload={},
        deterministic_value=None,
        incident_id=incident_id,
        database_url=db,
    )
    errors = validate_semantics(parsed, context, db)
    assert [error.code for error in errors] == ["invalid_pseudonym"]
    assert "HOST-9999" in errors[0].message


def test_resume_after_crash_keeps_scope(
    scope_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resumed analysis rebuilds the same scope from agent_steps."""
    from corvus.llm.transport import TransportError

    db = scope_db
    by_uid = _events_by_uid()
    loader_uids = ("wazuh-1", "wazuh-3")
    adapter_uids = ("wazuh-1", "wazuh-3", "wazuh-4")
    adapter = FakeAdapter([by_uid[uid] for uid in adapter_uids])
    rows = [_row_from_event(by_uid[uid]) for uid in loader_uids]
    incident_id = _seed_incident(db, key="scope-resume", uids=loader_uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=loader_uids)
    host_a = _pseudo(db, "host", HOST_A)
    pivot_ip = _pseudo(db, "ip", "203.0.113.7")
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-s1",
                "get_events",
                {
                    "host": host_a,
                    "start": START_ISO,
                    "end": END_ISO,
                    "limit": 10,
                },
            ),
        ),
    )

    class _BoomTransport:
        """First tool turn succeeds, the next transport try raises."""

        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def __call__(self, backend: Any, messages: Any, **kwargs: Any) -> Attempt:
            self.calls.append({"messages": list(messages)})
            if len(self.calls) == 1:
                return first
            raise TransportError("boom")

    import corvus.llm.call as call_module

    boom = _BoomTransport()
    monkeypatch.setattr(call_module.transport_module, "run_attempt", boom)
    outcome1 = run_analysis(
        incident_id,
        lang="en",
        database_url=db,
        adapter=adapter,
        evidence_loader=lambda _incident: list(rows),
        backend=_cloud_backend(),
        prices=_zero_prices("stub-cloud"),
        egress_filter=_egress_filter(),
    )
    assert outcome1.status == "ai_failed"
    steps = _load_steps(db, incident_id)
    assert len(steps) == 1
    assert pivot_ip in set(steps[0].shown_pseudonyms)
    timeline = (
        f"The {host_a} host contacted the {pivot_ip} address and the logs show it"
    )
    response = f"Isolate the {host_a} host and block the {pivot_ip} address now"
    uncertainty = f"The {host_a} host role and the {pivot_ip} address scope need review"
    good = _verdict_with(
        uid=loader_uids[0],
        timeline=timeline,
        response=response,
        uncertainty=uncertainty,
    )
    _patch_transport(monkeypatch, [_script_attempt(good)])
    outcome2 = run_analysis(
        incident_id,
        lang="en",
        database_url=db,
        adapter=adapter,
        evidence_loader=lambda _incident: list(rows),
        backend=_cloud_backend(),
        prices=_zero_prices("stub-cloud"),
        egress_filter=_egress_filter(),
    )
    assert outcome2.status == "resolved"


def test_global_fallback_documents_remaining_callers(scope_db: str) -> None:
    """Only callers without a scope rely on the global pseudonym table.

    Triage (``valid_pseudonyms=None``) falls back to ``SELECT pseudonym
    FROM pseudonyms``; the analysis path always sets an explicit scope
    and never falls back.
    """
    db = scope_db
    host_a = _pseudo(db, "host", HOST_A)
    parsed = {
        "summary": f"The {host_a} host ran a command and the logs show it",
        "verdict": "malicious",
        "severity_id": 3,
        "evidence_event_uids": ["e1"],
        "language": "en",
    }
    fallback_context = CallContext(
        event_uids=["e1"],
        deterministic_floor=3,
        language="en",
        valid_techniques=set(),
        valid_pseudonyms=None,
        payload={},
        deterministic_value=None,
        incident_id=None,
        database_url=db,
    )
    assert validate_semantics(parsed, fallback_context, db) == []
    unknown = dict(parsed, summary="The HOST-9999 host ran a command and logs show it")
    errors = validate_semantics(unknown, fallback_context, db)
    assert [error.code for error in errors] == ["invalid_pseudonym"]
    scoped = CallContext(
        event_uids=["e1"],
        deterministic_floor=3,
        language="en",
        valid_techniques=set(),
        valid_pseudonyms=set(),
        payload={},
        deterministic_value=None,
        incident_id=None,
        database_url=db,
    )
    scoped_errors = validate_semantics(parsed, scoped, db)
    assert [error.code for error in scoped_errors] == ["invalid_pseudonym"]
    by_uid = _events_by_uid()
    loader_uids = ("wazuh-1", "wazuh-3")
    rows = [_row_from_event(by_uid[uid]) for uid in loader_uids]
    incident_id = _seed_incident(db, key="scope-doc", uids=loader_uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=loader_uids)
    from corvus.llm.agent import _incident_entities

    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM incident_analyses WHERE incident_id = %s"
                " AND stage = 'triage'",
                (incident_id,),
            )
            stored = cur.fetchone()
            assert stored is not None
            condensed = dict((stored[0] or {}).get("condensed") or {})
    entities = _incident_entities(rows, condensed)
    scope = _analysis_scope_pseudonyms(db, entities, [])
    assert host_a in scope
    assert scope != set()
