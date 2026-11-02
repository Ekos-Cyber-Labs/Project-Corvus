"""Verdict scope admits pseudonyms the payload actually emitted.

No paid API calls: the transport entry is monkeypatched with scripted
attempts; every case builds a throwaway database through the shared
guard in ``tests/conftest.py``.

Incidents are built from ``tests/fixtures/siem_events.py`` (real OCSF
shapes, RFC 5737 addresses, ``example.com`` hosts). The free-text IP
``198.51.100.99`` appears only in the triage summary, never in a
typed loader field: the pseudonymizer assigns it a pseudonym by scan
and emits it into the model-bound payload, but it is not an incident
entity and no tool shows it. The verdict may cite it (emitted union)
while the tool allowlist still refuses it as a filter.
"""

from __future__ import annotations

import json
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from corvus.adapters.siem import FakeAdapter
from corvus.guardrails.pseudonymizer import Pseudonymizer
from corvus.llm.agent import _analysis_scope_pseudonyms, run_analysis
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

#: Free-text-only IP: triage summary mentions it, no loader field holds it.
FREETEXT_IP = "198.51.100.99"


@pytest.fixture
def emitted_db() -> Any:
    """Throwaway Postgres with migrations applied (guarded, never skips)."""
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


def _cloud_backend(model: str = "stub-cloud") -> BackendConfig:
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
    def __init__(self, scripts: list[Any]) -> None:
        self._scripts = list(scripts)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, backend: Any, messages: Any, **kwargs: Any) -> Attempt:
        self.calls.append({"messages": list(messages)})
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


def _seed_incident(db: str, *, key: str, uids: tuple[str, ...]) -> int:
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
    summary: str | None = None,
) -> None:
    condensed = {
        "summary": summary or f"Account {user} logged on to {host} and ran a command",
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
    pseudo = Pseudonymizer(db).get_or_create(kind, raw)
    assert pseudo is not None
    return pseudo


def _verdict_with(*, uid: str, token: str) -> str:
    return json.dumps(
        {
            "verdict": "true_positive",
            "severity_id": 3,
            "confidence": 0.81,
            "timeline": [
                {
                    "time": START_ISO,
                    "event_uid": uid,
                    "description": f"The {token} contacted host, logs show it",
                }
            ],
            "response_plan": [f"Block the {token} address and review the logs now"],
            "visibility_gaps": [],
            "uncertainties": [f"The {token} address scope needs review now"],
            "language": "en",
        }
    )


def _events_by_uid() -> dict[str, Any]:
    return {event.metadata.uid: event for event in make_siem_fixture_events()}


def test_emitted_freetext_pseudonym_may_be_cited(
    emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(1) A pseudonym emitted for a free-text token is verdict-valid."""
    db = emitted_db
    by_uid = _events_by_uid()
    uids = ("wazuh-1", "wazuh-3")
    adapter = FakeAdapter([by_uid[uid] for uid in uids])
    rows = [_row_from_event(by_uid[uid]) for uid in uids]
    incident_id = _seed_incident(db, key="emitted-cite", uids=uids)
    _seed_triage(
        db,
        incident_id,
        host=HOST_A,
        user=USER_A,
        uids=uids,
        summary=(
            f"Account {USER_A} on {HOST_A} contacted {FREETEXT_IP} and ran a command"
        ),
    )
    freetext_pseudo = _pseudo(db, "ip", FREETEXT_IP)
    from corvus.guardrails.payload import prepare_payload
    from corvus.llm.agent import _incident_entities, _require_condensed

    condensed = _require_condensed(db, incident_id)
    entities = _incident_entities(rows, condensed)
    prepared = prepare_payload(
        {"condensed": condensed},
        _cloud_backend(),
        database_url=db,
        entities=entities,
    )
    assert freetext_pseudo in prepared.emitted_pseudonyms
    # The token is not an incident entity and no tool showed it ...
    entity_scope = incident_scope_pseudonyms(db, entities, [])
    assert freetext_pseudo not in entity_scope
    # ... yet the verdict scope admits it.
    from corvus.llm.agent import _load_steps

    scope = _analysis_scope_pseudonyms(
        db,
        entities,
        _load_steps(db, incident_id),
        prepared.emitted_pseudonyms,
    )
    assert freetext_pseudo in scope
    good = _verdict_with(uid=uids[0], token=freetext_pseudo)
    stub = _patch_transport(monkeypatch, [_script_attempt(good)])
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
    assert stub.calls, "transport was never called"
    assert outcome.status == "resolved"
    assert outcome.attempts == 1


def test_attacker_literal_pseudonym_still_rejected(
    emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(2) An attacker-typed other-incident token is rejected in the verdict."""
    db = emitted_db
    by_uid = _events_by_uid()
    uids = ("wazuh-1", "wazuh-3")
    rows = [_row_from_event(by_uid[uid]) for uid in uids]
    other = _seed_incident(db, key="emitted-other", uids=("wazuh-5",))
    _seed_triage(db, other, host=HOST_B, user=USER_B, uids=("wazuh-5",))
    host_b = _pseudo(db, "host", HOST_B)
    # The attacker writes the other incident's real token into a command line.
    rows[0] = dict(rows[0])
    rows[0]["data"] = dict(rows[0]["data"])
    rows[0]["data"]["process"] = {"cmd_line": f"echo {host_b}"}
    incident_id = _seed_incident(db, key="emitted-victim", uids=uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=uids)
    host_a = _pseudo(db, "host", HOST_A)
    adapter = FakeAdapter([by_uid[uid] for uid in uids])
    bad = _verdict_with(uid=uids[0], token=host_b)
    good = _verdict_with(uid=uids[0], token=host_a)
    stub = _patch_transport(monkeypatch, [_script_attempt(bad), _script_attempt(good)])
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
    assert stub.calls
    assert outcome.status == "resolved"
    assert outcome.attempts == 2
    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT errors FROM llm_attempts"
                " WHERE incident_id = %s ORDER BY id ASC",
                (incident_id,),
            )
            attempts = [row[0] for row in cur.fetchall()]
    codes = [str(item.get("code")) for item in (attempts[0] or [])]
    assert "invalid_pseudonym" in codes


def test_tool_allowlist_ignores_emitted_pseudonym(
    emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(3) An emitted-only pseudonym grants no pivoting rights."""
    db = emitted_db
    by_uid = _events_by_uid()
    uids = ("wazuh-1", "wazuh-3")
    adapter = FakeAdapter([by_uid[uid] for uid in uids])
    rows = [_row_from_event(by_uid[uid]) for uid in uids]
    incident_id = _seed_incident(db, key="emitted-allow", uids=uids)
    _seed_triage(
        db,
        incident_id,
        host=HOST_A,
        user=USER_A,
        uids=uids,
        summary=f"Host {HOST_A} contacted {FREETEXT_IP} during the window",
    )
    freetext_pseudo = _pseudo(db, "ip", FREETEXT_IP)
    host_a = _pseudo(db, "host", HOST_A)
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-e1",
                "get_events",
                {"ip": freetext_pseudo, "start": START_ISO, "end": END_ISO},
            ),
        ),
    )
    good = _verdict_with(uid=uids[0], token=freetext_pseudo)
    stub = _patch_transport(monkeypatch, [first, _script_attempt(good)])
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
    assert stub.calls
    assert outcome.status == "resolved"
    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT result_summary, shown_pseudonyms FROM agent_steps"
                " WHERE incident_id = %s ORDER BY step_number ASC",
                (incident_id,),
            )
            steps = cur.fetchall()
    assert steps, "expected a persisted tool step"
    assert "unknown pseudonym" in str(steps[0][0])
    shown_union = {token for row in steps for token in (row[1] or [])}
    assert freetext_pseudo not in shown_union
    assert host_a not in shown_union


def test_resume_rebuilds_emitted_scope(
    emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(4) A resumed run rebuilds the same emitted-in-payload scope."""
    from corvus.llm.transport import TransportError

    db = emitted_db
    by_uid = _events_by_uid()
    uids = ("wazuh-1", "wazuh-3")
    adapter = FakeAdapter([by_uid[uid] for uid in uids])
    rows = [_row_from_event(by_uid[uid]) for uid in uids]
    incident_id = _seed_incident(db, key="emitted-resume", uids=uids)
    _seed_triage(
        db,
        incident_id,
        host=HOST_A,
        user=USER_A,
        uids=uids,
        summary=f"Host {HOST_A} contacted {FREETEXT_IP} during the window",
    )
    freetext_pseudo = _pseudo(db, "ip", FREETEXT_IP)
    host_a = _pseudo(db, "host", HOST_A)
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-r1",
                "get_events",
                {"host": host_a, "start": START_ISO, "end": END_ISO, "limit": 10},
            ),
        ),
    )

    class _BoomTransport:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, backend: Any, messages: Any, **kwargs: Any) -> Attempt:
            self.calls += 1
            if self.calls == 1:
                return first
            raise TransportError("boom-after-first-turn")

    import corvus.llm.call as call_module

    monkeypatch.setattr(call_module.transport_module, "run_attempt", _BoomTransport())
    try:
        run_analysis(
            incident_id,
            lang="en",
            database_url=db,
            adapter=adapter,
            evidence_loader=lambda _incident: list(rows),
            backend=_cloud_backend(),
            prices=_zero_prices("stub-cloud"),
            egress_filter=_egress_filter(),
        )
    except TransportError:
        pass
    from corvus.llm.agent import _incident_entities, _require_condensed
    from corvus.llm.agent import _load_steps as _steps

    steps = _steps(db, incident_id)
    assert steps, "expected a persisted tool step before the crash"
    condensed = _require_condensed(db, incident_id)
    entities = _incident_entities(rows, condensed)
    from corvus.guardrails.payload import prepare_payload as _prepare_resume

    resumed_emitted = _prepare_resume(
        {"condensed": condensed},
        _cloud_backend(),
        database_url=db,
        entities=entities,
    ).emitted_pseudonyms
    resumed_scope = _analysis_scope_pseudonyms(db, entities, steps, resumed_emitted)
    assert freetext_pseudo in resumed_scope
    good = _verdict_with(uid=uids[0], token=freetext_pseudo)
    _patch_transport(monkeypatch, [_script_attempt(good)])
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
    assert outcome.status == "resolved"
    assert outcome.attempts == 1


def test_emitted_scope_matches_validator_directly(emitted_db: str) -> None:
    """The emitted union passes validator 3 while the entity scope fails it."""
    db = emitted_db
    by_uid = _events_by_uid()
    uids = ("wazuh-1", "wazuh-3")
    rows = [_row_from_event(by_uid[uid]) for uid in uids]
    incident_id = _seed_incident(db, key="emitted-direct", uids=uids)
    _seed_triage(
        db,
        incident_id,
        host=HOST_A,
        user=USER_A,
        uids=uids,
        summary=f"Host {HOST_A} contacted {FREETEXT_IP} during the window",
    )
    freetext_pseudo = _pseudo(db, "ip", FREETEXT_IP)
    from corvus.llm.agent import _incident_entities, _require_condensed
    from corvus.llm.agent import _load_steps as _steps

    condensed = _require_condensed(db, incident_id)
    entities = _incident_entities(rows, condensed)
    parsed = json.loads(_verdict_with(uid=uids[0], token=freetext_pseudo))
    narrow = CallContext(
        event_uids=list(uids),
        deterministic_floor=3,
        language="en",
        valid_techniques={"T1059"},
        valid_pseudonyms=incident_scope_pseudonyms(db, entities, []),
        payload={},
        deterministic_value=None,
        incident_id=incident_id,
        database_url=db,
    )
    assert any(
        error.code == "invalid_pseudonym"
        for error in validate_semantics(parsed, narrow, db)
    )
    from corvus.guardrails.payload import prepare_payload

    emitted = prepare_payload(
        {"condensed": condensed},
        _cloud_backend(),
        database_url=db,
        entities=entities,
    ).emitted_pseudonyms
    assert freetext_pseudo in emitted
    wide = CallContext(
        event_uids=list(uids),
        deterministic_floor=3,
        language="en",
        valid_techniques={"T1059"},
        valid_pseudonyms=_analysis_scope_pseudonyms(
            db, entities, _steps(db, incident_id), emitted
        ),
        payload={},
        deterministic_value=None,
        incident_id=incident_id,
        database_url=db,
    )
    assert validate_semantics(parsed, wide, db) == []
