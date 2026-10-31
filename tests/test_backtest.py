"""Tests for the deterministic Sigma backtest (``corvus/learning/backtest``).

Unit tests run against tiny replay stores built from REAL archive
lines (``tests/fixtures/linux_synth_attack.json`` and
``tests/fixtures/linux_synth_baseline.json``, copied verbatim from
the lab archives); every rejection code is pinned, and nothing here
may crash or hang. The golden control rule
(``tests/fixtures/rules/linux_golden_rule.yml``) is proven accepted
against the real stores, with its deliberately broad sibling
rejected, in the integration tests below.
"""

from __future__ import annotations

import glob
import re
import time
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest

from corvus.adapters.replay.linux_loader import load_linux_path
from corvus.learning.backtest import (
    ALL_CODES,
    BacktestResult,
    _run_with_timeout,
    backtest,
)

FIXTURES = Path("tests/fixtures")
GOLDEN = (FIXTURES / "rules" / "linux_golden_rule.yml").read_text(encoding="utf-8")
BROAD = (FIXTURES / "rules" / "linux_golden_broad.yml").read_text(encoding="utf-8")

BASELINE_DIR = "data/replay-linux-baseline"
CHAIN_DIR = "data/replay-linux-chain1"

#: Real chain uids for the golden control (sudo find writing
#: authorized_keys, step 6 of chain 1; deterministic content hashes).
GOLDEN_UIDS = [
    "lnx-d7bea80358fc93ab",
    "lnx-f749ba60b31e41e4",
    "lnx-22e99900825434c9",
]

RULE_HEAD = """title: Probe {name}
id: 22222222-2222-4222-8222-222222222222
status: {status}
description: Probe rule for backtest tests.
author: Probe Author
logsource:
  product: linux
  category: process_creation
detection:
{{body}}
level: {level}
"""

_RULE_COUNTER = 0


def probe_rule(body: str, level: str = "medium", status: str = "test") -> str:
    """Render one Linux process_creation probe with a unique id."""
    global _RULE_COUNTER
    _RULE_COUNTER += 1
    text = RULE_HEAD.format(name=f"probe-{_RULE_COUNTER}", status=status, level=level)
    return text.replace(
        "22222222-2222-4222-8222-222222222222",
        f"22222222-2222-4222-8{_RULE_COUNTER:03d}-222222222222",
        1,
    ).replace("{body}", body)


def selection_body(field_lines: str, condition: str = "selection") -> str:
    """Wrap detection selections (already indented) with a condition."""
    return f"{field_lines}  condition: {condition}\n"


@pytest.fixture(scope="module")
def synth_stores(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Tiny attack/baseline stores from the real-record fixtures."""
    root = tmp_path_factory.mktemp("synth")
    chain = root / "chain"
    base = root / "base"
    attack = load_linux_path(
        FIXTURES / "linux_synth_attack.json",
        replay_dir=chain,
        data_dir=FIXTURES,
    )
    benign = load_linux_path(
        FIXTURES / "linux_synth_baseline.json",
        replay_dir=base,
        data_dir=FIXTURES,
    )
    assert attack.events_total == 2
    assert benign.events_total == 2
    uids: list[str] = []
    for path in sorted((chain / "events").glob("*.parquet")):
        uids.extend(pq.read_table(path, columns=["uid"]).column("uid").to_pylist())
    assert len(uids) == 2
    return {"chain": str(chain), "base": str(base), "uids": uids}


def call(
    sigma_text: object,
    target: object,
    stores: dict[str, Any],
) -> BacktestResult:
    """Run the backtest over the synthetic stores (never raises)."""
    return backtest(
        sigma_text,  # type: ignore[arg-type]
        target,  # type: ignore[arg-type]
        baseline_dir=str(stores["base"]),
        chain_dir=str(stores["chain"]),
    )


# Malformed input --------------------------------------------------------


def test_empty_and_wrong_types_are_bad_input(synth_stores: dict[str, Any]) -> None:
    assert call("", {"event_uids": ["x"]}, synth_stores).codes == ["bad_input"]
    assert call(None, {"event_uids": ["x"]}, synth_stores).codes == ["bad_input"]
    assert call(GOLDEN, ["not-a-mapping"], synth_stores).codes == ["bad_input"]
    assert call(GOLDEN, {"bogus": 1}, synth_stores).codes == ["empty_target"]


def test_invalid_yaml_reports_parse_error(synth_stores: dict[str, Any]) -> None:
    result = call("detection: [unclosed", {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["parse_error"]
    assert result.accepted is False
    assert result.detail["note"]


def test_two_rules_in_one_file_is_rule_count(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    Image|endswith: '/find'\n")
    two = probe_rule(body) + "\n---\n" + probe_rule(body)
    assert call(two, {"event_uids": ["x"]}, synth_stores).codes == ["rule_count"]


def test_oversized_rule_is_too_large(synth_stores: dict[str, Any]) -> None:
    body = selection_body(
        "  selection:\n    CommandLine|contains: '" + "A" * 1_000_100 + "'\n"
    )
    result = call(probe_rule(body), {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["too_large"]


def test_alias_spam_is_yaml_bomb(synth_stores: dict[str, Any]) -> None:
    lines = probe_rule(
        selection_body("  selection:\n    Image|endswith: '/find'\n")
    ).splitlines()
    lines.append("extra:")
    lines.extend(f"  k{n}: *alias{n}" for n in range(60))
    result = call("\n".join(lines) + "\n", {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["yaml_bomb"]


def test_deep_indentation_is_too_deep(synth_stores: dict[str, Any]) -> None:
    deep = "  selection:\n"
    pad = "    "
    for level in range(50):
        deep += f"{pad}k{level}:\n"
        pad += "  "
    deep += f"{pad}Image: '/find'\n"
    result = call(
        probe_rule(selection_body(deep)),
        {"event_uids": ["x"]},
        synth_stores,
    )
    assert result.codes == ["too_deep"]


# Routing and constructs --------------------------------------------------


def test_auditd_service_rule_is_unroutable(synth_stores: dict[str, Any]) -> None:
    auditd_rule = """title: Auditd probe
id: 33333333-3333-4333-8333-333333333333
status: test
description: Probe.
author: Probe Author
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: 'SYSCALL'
  condition: selection
level: medium
"""
    result = call(auditd_rule, {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["unroutable"]


def test_unmapped_field_is_skipped_not_nulled(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    ParentImage: '/usr/bin/bash'\n")
    result = call(probe_rule(body), {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["unmapped_field"]
    assert "ParentImage" in result.detail["note"]


def test_correlation_rule_is_unsupported(synth_stores: dict[str, Any]) -> None:
    # pySigma rejects unknown levels and Python-only regex constructs
    # at parse time, so the load-stage unsupported path is pinned
    # with a correlation rule: it parses, then the verifier refuses
    # it without evaluating.
    body = selection_body("  selection:\n    Image|endswith: '/find'\n")
    leaf = probe_rule(body)
    leaf_id = re.search(r"^id: (\S+)", leaf, re.MULTILINE)
    assert leaf_id is not None
    reference = leaf_id.group(1)
    correlation = f"""title: Correlation probe
id: 77777777-7777-4777-8777-777777777777
status: test
description: Probe.
correlation:
  type: temporal
  rules:
    - {reference}
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 3
"""
    result = call(leaf + "\n---\n" + correlation, {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["unsupported_construct"]


def test_double_negation_is_exclusion(synth_stores: dict[str, Any]) -> None:
    body = (
        "  selection:\n    Image|endswith: '/find'\n"
        "  filter_a:\n    CommandLine|contains: 'zzz-no-such-token'\n"
        "  filter_b:\n    CommandLine|contains: 'yyy-no-such-token'\n"
        "  condition: selection and not filter_a and not filter_b\n"
    )
    result = call(probe_rule(body), {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["exclusion"]


def test_short_contains_is_over_broad(synth_stores: dict[str, Any]) -> None:
    result = call(BROAD, {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["over_broad_literal"]
    assert result.cost == {}


def test_leading_wildcard_regex_rejected(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    CommandLine|re: '.*evil.*'\n")
    result = call(probe_rule(body), {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["leading_wildcard_regex"]


#: Generous wall budget proving the hostile-regex test rejects fast.
PARSE_BUDGET_S = 30.0


def test_nested_quantifier_rejected_without_hang(
    synth_stores: dict[str, Any],
) -> None:
    body = selection_body("  selection:\n    CommandLine|re: '(a+)+b'\n")
    started = time.monotonic()
    result = call(probe_rule(body), {"event_uids": ["x"]}, synth_stores)
    assert result.codes == ["dangerous_regex"]
    assert time.monotonic() - started < PARSE_BUDGET_S


def test_critical_level_rejected(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    Image|endswith: '/find'\n")
    result = call(
        probe_rule(body, level="critical"), {"event_uids": ["x"]}, synth_stores
    )
    assert result.codes == ["level_too_high"]


def test_unicode_and_control_chars_never_crash(
    synth_stores: dict[str, Any],
) -> None:
    body = '  selection:\n    CommandLine|contains: "caf\xe9\\u0007"\n'
    result = call(probe_rule(body), {"event_uids": ["x"]}, synth_stores)
    assert result.accepted in (True, False)
    assert result.codes and result.codes[0] in ALL_CODES
    assert isinstance(result.to_dict(), dict)


# Targets -----------------------------------------------------------------


def test_empty_target(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    Image|endswith: '/find'\n")
    assert call(probe_rule(body), {"event_uids": []}, synth_stores).codes == [
        "empty_target"
    ]


def test_unknown_target_uid(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    Image|endswith: '/find'\n")
    result = call(
        probe_rule(body), {"event_uids": ["uid-that-does-not-exist"]}, synth_stores
    )
    assert result.codes == ["unknown_target_uid"]


def test_rule_matching_nothing(synth_stores: dict[str, Any]) -> None:
    body = selection_body("  selection:\n    Image|endswith: '/nonexistent-xyz'\n")
    result = call(
        probe_rule(body), {"event_uids": [synth_stores["uids"][0]]}, synth_stores
    )
    assert result.codes == ["no_target_match"]
    assert result.target_total == 1
    assert result.baseline_count == 0


def test_host_window_target_resolves_scope(synth_stores: dict[str, Any]) -> None:
    files = sorted(glob.glob(f"{synth_stores['chain']}/events/*.parquet"))
    assert len(files) == 1
    table = pq.read_table(files[0], columns=["host", "time"])
    hosts = table.column("host").to_pylist()
    moments = sorted(table.column("time").to_pylist())
    body = selection_body("  selection:\n    Image|endswith: '/nonexistent-xyz'\n")
    result = call(
        probe_rule(body),
        {"host": hosts[0], "start": moments[0] - 1, "end": moments[-1] + 1},
        synth_stores,
    )
    assert result.codes == ["no_target_match"]
    assert result.scope["event_count"] == 2
    assert result.scope["hosts"] == [hosts[0]]
    assert result.scope["time_spread_ms"] == moments[-1] - moments[0]


def test_timeout_helper_distinguishes_error() -> None:
    def _boom() -> None:
        raise RuntimeError("boom")

    assert _run_with_timeout(_boom, 5.0)[0] == "error"

    def _slow() -> str:
        time.sleep(5.0)
        return "late"

    assert _run_with_timeout(_slow, 0.05)[0] == "timeout"
    assert _run_with_timeout(lambda: 1, 5.0) == ("ok", 1)


# Real-store integration ---------------------------------------------------


@pytest.mark.integration
def test_golden_rule_accepted_on_real_stores() -> None:
    result = backtest(GOLDEN, {"event_uids": GOLDEN_UIDS})
    assert result.accepted, result.codes
    assert result.codes == ["accepted"]
    assert sorted(result.target_matched) == [
        "lnx-d7bea80358fc93ab",
        "lnx-f749ba60b31e41e4",
    ]
    assert result.baseline_count == 0
    assert result.baseline_sample_uids == []
    assert result.scope["hosts"] == ["corvus-victim"]
    assert result.cost["rows_scanned"] > 0


@pytest.mark.integration
def test_golden_broad_variant_rejected() -> None:
    result = backtest(BROAD, {"event_uids": GOLDEN_UIDS})
    assert result.accepted is False
    assert result.codes == ["over_broad_literal"]


@pytest.mark.integration
def test_baseline_firing_rule_rejected() -> None:
    or_rule = GOLDEN.replace(
        "  condition: sel_img and sel_key and sel_exec",
        "  condition: sel_img and (sel_key or sel_exec)",
    )
    result = backtest(or_rule, {"event_uids": GOLDEN_UIDS})
    assert result.accepted is False
    assert result.codes == ["baseline_match"]
    assert result.baseline_count > 0
    assert len(result.baseline_sample_uids) <= 10


@pytest.mark.integration
def test_single_exclusion_tolerated() -> None:
    single_not = GOLDEN.replace(
        "  sel_exec:\n    CommandLine|contains: '-exec'\n"
        "  condition: sel_img and sel_key and sel_exec",
        "  sel_exec:\n    CommandLine|contains: '-exec'\n"
        "  sel_none:\n    Image: '/nonexistent-xyz'\n"
        "  condition: sel_img and sel_key and sel_exec and not sel_none",
    )
    result = backtest(single_not, {"event_uids": GOLDEN_UIDS})
    assert result.accepted, result.codes


@pytest.mark.integration
def test_host_window_target_on_real_chain() -> None:
    result = backtest(
        GOLDEN,
        {
            "host": "corvus-victim",
            "start": "2026-10-31T04:25:26.828Z",
            "end": "2026-10-31T04:25:38.752Z",
        },
    )
    assert result.accepted, result.codes
    assert result.target_total > 2
    assert len(result.target_matched) >= 2
