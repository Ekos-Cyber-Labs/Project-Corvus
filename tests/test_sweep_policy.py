"""Pure policy table tests for the automatic sweep (no database).

Covers :func:`corvus.live.sweep.decide` (threshold, injection
override, ranking support, cap, budget) and
:func:`corvus.live.sweep.effective_policy` (flag > env > default
precedence plus every invalid value rejected).
"""

from __future__ import annotations

import pytest

from corvus.live.sweep import Candidate, SweepPolicy, decide, effective_policy


def _policy(**over: object) -> SweepPolicy:
    base: dict[str, object] = {
        "min_floor": 4,
        "max_analyses": 5,
        "always_analyze_injection": True,
        "spend_cap_usd": 100.0,
        "lang": "en",
        "interval_seconds": 300.0,
    }
    base.update(over)
    return SweepPolicy(**base)  # type: ignore[arg-type]


def test_decide_analyzes_at_or_above_floor() -> None:
    policy = _policy()
    assert decide(Candidate(1, 4, 1, False), policy, 0.0, 0) == (
        "analyze",
        "selected",
    )
    assert decide(Candidate(2, 6, 1, False), policy, 0.0, 0) == (
        "analyze",
        "selected",
    )


def test_decide_skips_below_floor() -> None:
    policy = _policy()
    assert decide(Candidate(1, 3, 10, False), policy, 0.0, 0) == (
        "skipped_policy",
        "below_min_floor",
    )


def test_decide_injection_override_on_and_off() -> None:
    low_injection = Candidate(1, 2, 1, True)
    assert decide(low_injection, _policy(), 0.0, 0) == ("analyze", "selected")
    off = _policy(always_analyze_injection=False)
    assert decide(low_injection, off, 0.0, 0) == (
        "skipped_policy",
        "below_min_floor",
    )


def test_decide_injection_does_not_bypass_budget_or_max() -> None:
    policy = _policy(max_analyses=0)
    assert decide(Candidate(1, 6, 1, True), policy, 0.0, 0) == (
        "skipped_policy",
        "max_analyses_reached",
    )
    assert decide(Candidate(1, 6, 1, True), _policy(), 100.0, 0) == (
        "skipped_budget",
        "over_spend_cap",
    )


def test_decide_max_analyses_stops_further_candidates() -> None:
    policy = _policy(max_analyses=1)
    assert decide(Candidate(1, 5, 1, False), policy, 0.0, 0)[0] == "analyze"
    assert decide(Candidate(2, 5, 1, False), policy, 0.0, 1) == (
        "skipped_policy",
        "max_analyses_reached",
    )


def test_decide_budget_boundary_is_exact() -> None:
    policy = _policy(spend_cap_usd=10.0)
    assert decide(Candidate(1, 6, 1, False), policy, 9.99, 0)[0] == "analyze"
    assert decide(Candidate(1, 6, 1, False), policy, 10.0, 0) == (
        "skipped_budget",
        "over_spend_cap",
    )


def _clear_sweep_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SWEEP_INTERVAL_SECONDS",
        "SWEEP_MIN_FLOOR",
        "SWEEP_MAX_ANALYSES",
        "SWEEP_ALWAYS_INJECTION",
        "SWEEP_LANG",
        "SPEND_CAP_USD",
    ):
        monkeypatch.delenv(name, raising=False)


def test_effective_policy_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_sweep_env(monkeypatch)
    policy = effective_policy()
    assert policy.min_floor == 4
    assert policy.max_analyses == 5
    assert policy.always_analyze_injection is True
    assert policy.spend_cap_usd == 100.0
    assert policy.lang == "en"
    assert policy.interval_seconds == 300.0


def test_effective_policy_env_overrides_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_sweep_env(monkeypatch)
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "60")
    monkeypatch.setenv("SWEEP_MIN_FLOOR", "critical")
    monkeypatch.setenv("SWEEP_MAX_ANALYSES", "2")
    monkeypatch.setenv("SWEEP_ALWAYS_INJECTION", "false")
    policy = effective_policy()
    assert policy.interval_seconds == 60.0
    assert policy.min_floor == 5
    assert policy.max_analyses == 2
    assert policy.always_analyze_injection is False


def test_effective_policy_flag_overrides_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_sweep_env(monkeypatch)
    monkeypatch.setenv("SWEEP_MIN_FLOOR", "low")
    monkeypatch.setenv("SWEEP_MAX_ANALYSES", "2")
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "60")
    monkeypatch.setenv("SWEEP_ALWAYS_INJECTION", "false")
    policy = effective_policy(
        min_floor="critical",
        max_analyses=3,
        always_analyze_injection=True,
        interval_seconds=120.0,
    )
    assert policy.min_floor == 5
    assert policy.max_analyses == 3
    assert policy.always_analyze_injection is True
    assert policy.interval_seconds == 120.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_floor": "fatal"},
        {"max_analyses": -1},
        {"max_analyses": 51},
        {"interval_seconds": 29.9},
        {"lang": "fr"},
        {"spend_cap_usd": -1.0},
    ],
)
def test_effective_policy_rejects_invalid_flags(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, object]
) -> None:
    _clear_sweep_env(monkeypatch)
    with pytest.raises(ValueError, match="(?i)must be|unknown"):
        effective_policy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name,value",
    [
        ("SWEEP_MIN_FLOOR", "bogus"),
        ("SWEEP_MAX_ANALYSES", "99"),
        ("SWEEP_INTERVAL_SECONDS", "10"),
        ("SWEEP_ALWAYS_INJECTION", "maybe"),
        ("SPEND_CAP_USD", "-5"),
    ],
)
def test_effective_policy_rejects_invalid_env(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    _clear_sweep_env(monkeypatch)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        effective_policy()
