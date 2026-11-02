"""Tool-result emitted pseudonyms belong to the verdict scope.

A pseudonym the pseudonymizer substitutes into a tool result's free
text (for example a command line holding a registered host that is
not in the first-turn payload and not in any typed field of that
result) is shown to the model, so a correct verdict citing it must
validate. The same token must still be refused as a ``get_events``
filter (emissions never grant pivoting rights), and an
attacker-typed literal pseudonym passing through the same result
must still be refused in the verdict.

No paid API calls: the transport entry is monkeypatched with scripted
attempts; every case builds a throwaway database through the shared
guard in ``tests/conftest.py``.
"""

from __future__ import annotations

import json
from typing import Any

import psycopg
import pytest

from corvus.adapters.siem import FakeAdapter
from corvus.guardrails.pseudonymizer import Pseudonymizer
from corvus.llm.agent import run_analysis
from corvus.llm.config import BackendConfig
from corvus.llm.price_book import ModelPrice
from corvus.llm.transport import Attempt, ToolCall
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls
from tests.fixtures.siem_events import make_siem_fixture_events

START_ISO = "2026-10-27T12:00:00Z"
END_ISO = "2026-10-27T13:00:00Z"

HOST_A = "web01.example.com"
USER_A = "EXAMPLE\\jdoe"

#: Registered host appearing only in free text: a typed loader field
#: names it (so it is an incident entity), but the condensed summary
#: never mentions it and no tool result carries it in a typed field.
SECRET_HOST = "secretws01.example.com"


@pytest.fixture
def tool_emitted_db() -> Any:
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
    from psycopg.types.json import Jsonb

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
    from psycopg.types.json import Jsonb

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
                    "description": f"The {token} host ran the chain step",
                }
            ],
            "response_plan": [f"Isolate the {token} host and review the logs now"],
            "visibility_gaps": [],
            "uncertainties": [f"The {token} host scope needs review now"],
            "language": "en",
        }
    )


def _setup_secret_chain(db: str, *, key: str) -> tuple[Any, list[dict[str, Any]], int]:
    """Build rows/adapter where a registered host lives only in free text.

    The secret host is known to the deployment (registered here, as an
    earlier incident's entity would be), but it is NOT one of this
    incident's entities: no loader row names it, the condensed summary
    never mentions it, and no served event carries it in a typed
    field. Only the tool result's command line holds the raw spelling,
    so the pseudonymizer substitutes it there (known-value
    replacement) and the emission is the model's only sighting.
    """
    by_uid = {event.metadata.uid: event for event in make_siem_fixture_events()}
    uids = ("wazuh-1", "wazuh-3")
    from corvus.normalize.ocsf import Process

    process_event = by_uid["wazuh-3"].model_copy(
        update={
            "process": Process(
                pid=1234,
                name="cmd.exe",
                cmd_line=f"C:\\Windows\\System32\\cmd.exe /c ping {SECRET_HOST}",
            )
        }
    )
    adapter = FakeAdapter([by_uid["wazuh-1"], process_event])
    rows = [_row_from_event(by_uid["wazuh-1"]), _row_from_event(by_uid["wazuh-3"])]
    # Register deployment-wide without making it an incident entity.
    assert Pseudonymizer(db).get_or_create("host", SECRET_HOST) is not None
    incident_id = _seed_incident(db, key=key, uids=uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=uids)
    return adapter, rows, incident_id


def test_tool_result_freetext_pseudonym_may_be_cited(
    tool_emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(1) A pseudonym emitted into a tool result cites cleanly."""
    db = tool_emitted_db
    adapter, rows, incident_id = _setup_secret_chain(db, key="tool-emit-cite")
    secret_pseudo = _pseudo(db, "host", SECRET_HOST)
    host_a = _pseudo(db, "host", HOST_A)
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-t1",
                "get_events",
                {"host": host_a, "start": START_ISO, "end": END_ISO, "limit": 10},
            ),
        ),
    )
    good = _verdict_with(uid="wazuh-1", token=secret_pseudo)
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
    assert outcome.attempts == 2


def test_tool_emitted_token_refused_as_filter(
    tool_emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(2) An emitted-only pseudonym grants no pivoting rights."""
    db = tool_emitted_db
    adapter, rows, incident_id = _setup_secret_chain(db, key="tool-emit-filter")
    secret_pseudo = _pseudo(db, "host", SECRET_HOST)
    host_a = _pseudo(db, "host", HOST_A)
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-f1",
                "get_events",
                {"host": host_a, "start": START_ISO, "end": END_ISO, "limit": 10},
            ),
        ),
    )
    second = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-f2",
                "get_events",
                {"host": secret_pseudo, "start": START_ISO, "end": END_ISO},
            ),
        ),
    )
    good = _verdict_with(uid="wazuh-1", token=host_a)
    stub = _patch_transport(monkeypatch, [first, second, _script_attempt(good)])
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
                "SELECT result_summary FROM agent_steps"
                " WHERE incident_id = %s ORDER BY step_number ASC",
                (incident_id,),
            )
            summaries = [row[0] for row in cur.fetchall()]
    assert len(summaries) == 2
    assert "unknown pseudonym" in str(summaries[1])


def test_attacker_literal_in_tool_result_still_refused(
    tool_emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(3) An attacker-typed literal passing through a result cites never."""
    db = tool_emitted_db
    by_uid = {event.metadata.uid: event for event in make_siem_fixture_events()}
    uids = ("wazuh-1", "wazuh-3")
    from corvus.normalize.ocsf import Process

    process_event = by_uid["wazuh-3"].model_copy(
        update={
            "process": Process(
                pid=1234,
                name="cmd.exe",
                cmd_line="C:\\Windows\\System32\\cmd.exe /c echo HOST-9999",
            )
        }
    )
    adapter = FakeAdapter([by_uid["wazuh-1"], process_event])
    rows = [_row_from_event(by_uid["wazuh-1"]), _row_from_event(by_uid["wazuh-3"])]
    incident_id = _seed_incident(db, key="tool-emit-literal", uids=uids)
    _seed_triage(db, incident_id, host=HOST_A, user=USER_A, uids=uids)
    host_a = _pseudo(db, "host", HOST_A)
    first = _script_attempt(
        None,
        finish_reason="tool_calls",
        tool_calls=(
            _tool_call(
                "c-l1",
                "get_events",
                {"host": host_a, "start": START_ISO, "end": END_ISO, "limit": 10},
            ),
        ),
    )
    bad = _verdict_with(uid="wazuh-1", token="HOST-9999")
    good = _verdict_with(uid="wazuh-1", token=host_a)
    stub = _patch_transport(
        monkeypatch, [first, _script_attempt(bad), _script_attempt(good)]
    )
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
    assert outcome.attempts == 3
    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT errors FROM llm_attempts"
                " WHERE incident_id = %s ORDER BY id ASC",
                (incident_id,),
            )
            attempts = [row[0] for row in cur.fetchall()]
    codes = [str(item.get("code")) for item in (attempts[1] or [])]
    assert "invalid_pseudonym" in codes


def test_resume_rebuilds_tool_emitted_scope(
    tool_emitted_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(4) A resumed run re-admits the tool-result emission."""
    from corvus.llm.transport import TransportError

    db = tool_emitted_db
    adapter, rows, incident_id = _setup_secret_chain(db, key="tool-emit-resume")
    secret_pseudo = _pseudo(db, "host", SECRET_HOST)
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
    with psycopg.connect(db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT step_number FROM agent_steps WHERE incident_id = %s",
                (incident_id,),
            )
            assert cur.fetchall(), "expected a persisted tool step before the crash"
    good = _verdict_with(uid="wazuh-1", token=secret_pseudo)
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
