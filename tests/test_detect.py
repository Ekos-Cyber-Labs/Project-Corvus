"""Tests for the Sigma replay detector (``corvus/detect``).

Hand-written fixtures only (RFC 5737 addresses, ``example.com``
hosts): process records with cased/missing fields exercise every
supported modifier, the case-mismatch test proves case-insensitive
matching end to end, and the negation-with-missing-field test pins
the Sigma null semantics (a field absent from the raw record
never matches a value but satisfies ``NOT``; a placeholder the
normalizer nulled still compares as the logged value, read from
the raw record).
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from corvus.adapters.replay import load_path
from corvus.adapters.replay.schema import findings_dir
from corvus.attack.dictionary import AttackDictionary
from corvus.detect import backend as backend_mod
from corvus.detect import mapping as mapping_mod
from corvus.detect.engine import MatchedEvent, evaluate
from corvus.detect.findings import (
    attacks_for_tags,
    build_finding,
    finding_uid,
)
from corvus.detect.mapping import GROUPS, extract_row, route_logsource
from corvus.detect.rules import (
    CompiledRule,
    compile_loaded,
    load_rules,
)
from tests.fixtures import windows_events as fx

RULE_HEAD = """title: Probe {name}
id: 11111111-1111-4111-8111-111111111111
status: test
description: Probe rule for tests.
author: Probe Author
logsource:
  product: windows
  {logsource}
detection:
{body}
level: {level}
"""

#: The standard fixture process image (single backslashes, Sigma style).
POWERSHELL_IMAGE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


_RULE_ID_COUNTER = 0


def make_rule(
    name: str,
    logsource: str,
    body: str,
    level: str = "high",
) -> str:
    """Render one Sigma rule YAML fragment (unique id per call)."""
    global _RULE_ID_COUNTER
    _RULE_ID_COUNTER += 1
    rule_id = f"11111111-1111-4111-8{_RULE_ID_COUNTER:03d}-111111111111"
    head = RULE_HEAD.replace("11111111-1111-4111-8111-111111111111", rule_id, 1)
    return head.format(name=name, logsource=logsource, body=body, level=level)


PROC_LOGSOURCE = "category: process_creation"
NET_LOGSOURCE = "category: network_connection"
IMG_LOGSOURCE = "category: image_load"


def proc_record(**overrides: object) -> dict[str, object]:
    """The standard process fixture with overrides (None drops the key)."""
    record = dict(fx.flat_sysmon_process())
    for key, value in overrides.items():
        if value is None:
            record.pop(key, None)
        else:
            record[key] = value
    return record  # type: ignore[return-value]


_RULES_DIR_COUNTER = 0


def write_rules(tmp_path: Path, rules: list[str]) -> Path:
    """Write rule YAML strings to a tmp rules dir (fresh subdir per call)."""
    global _RULES_DIR_COUNTER
    _RULES_DIR_COUNTER += 1
    rules_dir = tmp_path / f"rules_{_RULES_DIR_COUNTER}"
    rules_dir.mkdir()
    for number, text in enumerate(rules):
        (rules_dir / f"rule_{number:03d}.yml").write_text(text, encoding="utf-8")
    return rules_dir


def write_store(tmp_path: Path, records: list[dict]) -> Path:
    """Load fixture records into a tmp replay store; return its dir."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    archive = data_dir / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "events.json", "\n".join(json.dumps(record) for record in records) + "\n"
        )
    replay_dir = tmp_path / "replay"
    summary = load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    assert summary.events_total == len(records)
    return replay_dir


def run_detect(
    replay_dir: Path, rules_dir: Path
) -> tuple[dict[str, set[str]], dict[str, MatchedEvent], object, list[CompiledRule]]:
    """Compile every rule and evaluate it over the store."""
    compiled, load_stats = load_rules(rules_dir)
    matches, infos, eval_stats = evaluate(replay_dir, compiled)
    return matches, infos, eval_stats, compiled


def attack_fixture() -> AttackDictionary:
    """Minimal ATT&CK dictionary: parent, sub, revoked, tactic-only."""
    return AttackDictionary.from_compact(
        {
            "tactics": {
                "execution": {"name": "Execution", "id": "TA9001"},
                "credential-access": {"name": "Credential Access", "id": "TA9002"},
            },
            "tactic_order": ["execution", "credential-access"],
            "techniques": {
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "tactics": ["execution"],
                    "is_subtechnique": False,
                    "parent": None,
                    "deprecated": False,
                    "revoked": False,
                    "revoked_by": None,
                },
                "T1059.001": {
                    "name": "PowerShell",
                    "tactics": ["execution"],
                    "is_subtechnique": True,
                    "parent": "T1059",
                    "deprecated": False,
                    "revoked": False,
                    "revoked_by": None,
                },
                "T1145": {
                    "name": "Private Keys",
                    "tactics": ["credential-access"],
                    "is_subtechnique": False,
                    "parent": None,
                    "deprecated": False,
                    "revoked": True,
                    "revoked_by": "T1552.004",
                },
                "T1552.004": {
                    "name": "Private Keys",
                    "tactics": ["credential-access"],
                    "is_subtechnique": True,
                    "parent": "T1552",
                    "deprecated": False,
                    "revoked": False,
                    "revoked_by": None,
                },
                "T1552": {
                    "name": "Unsecured Credentials",
                    "tactics": ["credential-access"],
                    "is_subtechnique": False,
                    "parent": None,
                    "deprecated": False,
                    "revoked": False,
                    "revoked_by": None,
                },
                "T1065": {
                    "name": "Uncommonly Used Port",
                    "tactics": ["execution"],
                    "is_subtechnique": False,
                    "parent": None,
                    "deprecated": True,
                    "revoked": False,
                    "revoked_by": None,
                },
            },
        }
    )


def matched_event_uids(
    tmp_path: Path, records: list[dict], rule_yaml: str
) -> tuple[set[str], list[dict]]:
    """Evaluate one rule over fixture records; return matched uids + rows."""
    from corvus.adapters.replay.schema import events_dir

    replay_dir = write_store(tmp_path, records)
    rules_dir = write_rules(tmp_path, [rule_yaml])
    matches, _, _, compiled = run_detect(replay_dir, rules_dir)
    assert len(compiled) == 1
    rows = pq.read_table(events_dir(replay_dir)).to_pylist()
    return matches[compiled[0].rule_id], rows


# Translation unit tests -------------------------------------------------


def test_like_becomes_ilike_and_glob_passes_through() -> None:
    out = backend_mod.translate_sqlite_to_duckdb(
        "SELECT * FROM slice WHERE Image LIKE '%cmd%' ESCAPE '\\' AND Image GLOB 'CMD*'"
    )
    assert "Image ILIKE '%cmd%' ESCAPE '\\'" in out
    assert "Image GLOB 'CMD*'" in out


def test_glob_backslash_doubling_matches_single_backslash() -> None:
    # SQLite GLOB reads a backslash literally; DuckDB GLOB treats
    # it as an escape, so the translator doubles lone backslashes.
    lone = "Image GLOB 'C:\Windows\*'"
    translated = backend_mod.translate_sqlite_to_duckdb(
        "SELECT * FROM slice WHERE " + lone
    )
    doubled = "Image GLOB 'C:\\\\Windows\\\\*'"
    assert doubled in translated
    pattern = "C:\\\\Windows\\\\*"
    connection = duckdb.connect()
    try:
        value = "C:" + chr(92) + "Windows" + chr(92) + "x.exe"
        assert connection.execute("SELECT ? GLOB ?", [value, pattern]).fetchall() == [
            (True,)
        ]
    finally:
        connection.close()


def test_bool_numeric_branch_is_dropped_for_text_storage() -> None:
    out = backend_mod.translate_sqlite_to_duckdb(
        "SELECT * FROM slice WHERE (Initiated='true' OR Initiated=1)"
    )
    assert out == "SELECT * FROM slice WHERE (Initiated='true')"
    connection = duckdb.connect()
    try:
        connection.execute("CREATE TABLE t (Initiated VARCHAR)")
        connection.execute("INSERT INTO t VALUES ('true'), ('false'), (NULL)")
        assert connection.execute(
            "SELECT count(*) FROM t WHERE Initiated='true'"
        ).fetchall() == [(1,)]
    finally:
        connection.close()


def test_like_inside_a_literal_is_not_rewritten() -> None:
    out = backend_mod.translate_sqlite_to_duckdb(
        "SELECT * FROM slice WHERE CommandLine LIKE '% LIKE %' ESCAPE '\\'"
    )
    assert out.count("ILIKE") == 1
    assert "'% LIKE %'" in out


def test_regexp_becomes_regexp_matches() -> None:
    out = backend_mod.translate_sqlite_to_duckdb(
        "SELECT * FROM slice WHERE CommandLine REGEXP '.*mimi[ck]atz.*'"
    )
    assert out == (
        "SELECT * FROM slice WHERE regexp_matches(CommandLine, '.*mimi[ck]atz.*')"
    )


def test_regexp_inside_a_literal_is_not_rewritten() -> None:
    out = backend_mod.translate_sqlite_to_duckdb(
        "SELECT * FROM slice WHERE CommandLine ILIKE '%REGEXP%' ESCAPE '\\'"
    )
    assert "regexp_matches" not in out


def test_duckdb_like_is_case_sensitive_and_ilike_is_not() -> None:
    """DuckDB proof: LIKE is case-sensitive, so ILIKE is required."""
    connection = duckdb.connect()
    try:
        assert connection.execute("SELECT 'ABC' LIKE 'abc'").fetchall() == [(False,)]
        assert connection.execute("SELECT 'ABC' ILIKE 'abc'").fetchall() == [(True,)]
        assert connection.execute("SELECT 'a_c' ILIKE 'A_C'").fetchall() == [(True,)]
        assert connection.execute("SELECT 'ABC' GLOB 'abc'").fetchall() == [(False,)]
        assert connection.execute("SELECT 'abc' GLOB 'a?c'").fetchall() == [(True,)]
    finally:
        connection.close()


def test_compiled_equality_uses_collate_nocase_and_stock_not_semantics() -> None:

    collection = SigmaCollection.from_yaml(
        make_rule(
            "null",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    Image: 'cmd.exe'\n"
            "  filter:\n"
            "    CommandLine: 'zzz'\n"
            "  condition: selection and not filter\n",
        )
    )
    only_rule = collection.rules[0]
    assert isinstance(only_rule, SigmaRule)
    sql = compile_loaded(only_rule)
    assert "COLLATE NOCASE" in sql
    # Stock backend semantics (Sigma): NOT wraps in COALESCE, so a
    # missing field satisfies the negated condition.
    assert "NOT COALESCE(" in sql


# Modifier end-to-end tests -----------------------------------------------


def test_contains_matches_case_insensitively(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "contains",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    CommandLine|contains: 'get-process'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1


def test_equality_matches_case_insensitively(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "equality",
            PROC_LOGSOURCE,
            "  selection:\n"
            f"    Image: '{POWERSHELL_IMAGE.lower()}'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1


def test_startswith_endswith_all_and_wildcards(tmp_path: Path) -> None:
    records = [
        proc_record(),
        proc_record(
            Image="C:\\WINDOWS\\NOTEPAD.EXE",
            CommandLine="NOTEPAD.EXE notes",
            EventIdx=201,
        ),
    ]
    cases = [
        (
            "  selection:\n"
            "    Image|startswith: 'c:\\windows\\system32'\n"
            "  condition: selection\n",
            1,
        ),
        (
            "  selection:\n    Image|endswith: 'NOTEPAD.EXE'\n  condition: selection\n",
            1,
        ),
        (
            "  selection:\n"
            "    CommandLine|contains|all:\n"
            "      - 'powershell'\n"
            "      - 'get-process'\n"
            "  condition: selection\n",
            1,
        ),
        ("  selection:\n    Image: 'C:\\\\WINDOWS\\\\*'\n  condition: selection\n", 2),
        (
            "  selection:\n"
            "    Image: 'C:\\\\Windows\\\\???????.EXE'\n"
            "  condition: selection\n",
            1,
        ),
        (
            "  selection:\n"
            "    Image: 'c:\\\\windows\\\\????pad.exe'\n"
            "  condition: selection\n",
            1,
        ),
        (
            "  selection:\n"
            "    Image: 'C:\\Windows\\no?ad.exe'\n"
            "  condition: selection\n",
            0,
        ),
    ]
    for body, expected in cases:
        matched, _ = matched_event_uids(
            tmp_path, records, make_rule("m", PROC_LOGSOURCE, body)
        )
        assert len(matched) == expected, body


def test_windash_and_base64offset(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "windash",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    CommandLine|contains|windash: '-NoProfile'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1
    blob = "cmd /c echo SGVsbG8gV29ybGQ="
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record(CommandLine=blob, EventIdx=202)],
        make_rule(
            "b64",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    CommandLine|base64offset|contains: 'Hello World'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1


def test_re_is_case_sensitive_and_checked(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "re",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    CommandLine|re: 'Get-.{3}cess'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1
    quiet, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "re-case",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    CommandLine|re: 'get-.{3}cess'\n"
            "  condition: selection\n",
        ),
    )
    assert len(quiet) == 0


def test_rejected_regex_skips_the_rule(tmp_path: Path) -> None:
    rules_dir = write_rules(
        tmp_path,
        [
            make_rule(
                "bad-re",
                PROC_LOGSOURCE,
                "  selection:\n    CommandLine|re: '(?<=x)y'\n  condition: selection\n",
            )
        ],
    )
    compiled, stats = load_rules(rules_dir)
    assert compiled == []
    assert stats.skipped.get("unsupported_construct") == 1


def test_cidr_matches(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [fx.flat_sysmon_network()],
        make_rule(
            "cidr",
            NET_LOGSOURCE,
            "  selection:\n"
            "    DestinationIp|cidr: '203.0.113.0/24'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1
    quiet, _ = matched_event_uids(
        tmp_path,
        [fx.flat_sysmon_network()],
        make_rule(
            "cidr-miss",
            NET_LOGSOURCE,
            "  selection:\n"
            "    DestinationIp|cidr: '198.51.100.0/24'\n"
            "  condition: selection\n",
        ),
    )
    assert len(quiet) == 0


def test_cased_is_case_sensitive(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "cased",
            PROC_LOGSOURCE,
            "  selection:\n"
            f"    Image|cased: '{POWERSHELL_IMAGE}'\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1
    quiet, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "cased-miss",
            PROC_LOGSOURCE,
            "  selection:\n"
            f"    Image|cased: '{POWERSHELL_IMAGE.lower()}'\n"
            "  condition: selection\n",
        ),
    )
    assert len(quiet) == 0


def test_fieldref_exists_and_null(tmp_path: Path) -> None:
    records = [
        proc_record(),
        proc_record(CommandLine="same-cmd", ParentCommandLine="same-cmd", EventIdx=203),
    ]
    matched, _ = matched_event_uids(
        tmp_path,
        records,
        make_rule(
            "fieldref",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    CommandLine|fieldref: ParentCommandLine\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1
    present, _ = matched_event_uids(
        tmp_path,
        records,
        make_rule(
            "exists",
            PROC_LOGSOURCE,
            "  selection:\n    CommandLine|exists: true\n  condition: selection\n",
        ),
    )
    assert len(present) == 2
    missing, _ = matched_event_uids(
        tmp_path,
        records,
        make_rule(
            "not-exists",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    OriginalFileName|exists: false\n"
            "  condition: selection\n",
        ),
    )
    assert len(missing) == 2
    null, _ = matched_event_uids(
        tmp_path,
        [proc_record(ParentImage=None, EventIdx=204)],
        make_rule(
            "null",
            PROC_LOGSOURCE,
            "  selection:\n    ParentImage: null\n  condition: selection\n",
        ),
    )
    assert len(null) == 1


def test_negation_with_missing_field_includes_the_row(tmp_path: Path) -> None:
    records = [
        proc_record(),
        proc_record(
            Image="C:\\Windows\\notepad.exe",
            CommandLine="notepad.exe notes",
            ParentCommandLine=None,
            EventIdx=205,
        ),
    ]
    matched, _ = matched_event_uids(
        tmp_path,
        records,
        make_rule(
            "negation",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    Image|contains: '.exe'\n"
            "  filter:\n"
            "    ParentCommandLine|contains: 'explorer'\n"
            "  condition: selection and not filter\n",
        ),
    )
    # Sigma semantics: the powershell row is excluded because the
    # filter positively matches its parent command line, but the
    # notepad row is included — its missing field matches no value,
    # so ``NOT`` over it is true.
    assert len(matched) == 1


def test_placeholder_value_excluded_by_not_filter(tmp_path: Path) -> None:
    # Security 4624 with IpAddress "-" in the raw record: the
    # normalizer nulls the typed endpoint, but the Sigma row carries
    # the logged "-", so ``not filter`` excludes it while the record
    # with no IpAddress key at all is included.
    dashed = dict(fx.flat_security_logon(success=True))
    dashed["IpAddress"] = "-"
    dashed["EventIdx"] = 106
    missing = dict(fx.flat_security_logon(success=True))
    missing.pop("IpAddress")
    missing["EventIdx"] = 107
    matched, _ = matched_event_uids(
        tmp_path,
        [dashed, missing],
        make_rule(
            "placeholder",
            "service: security",
            "  selection:\n"
            "    EventID: 4624\n"
            "  filter:\n"
            "    IpAddress: '-'\n"
            "  condition: selection and not filter\n",
            level="medium",
        ),
    )
    assert len(matched) == 1


def write_event_store(tmp_path: Path, events: list[dict]) -> Path:
    """Write OCSF event dicts straight to a tmp replay store.

    Bypasses the normalizer so tests can use raw layouts (such as the
    trimmed EVTX ``System``/``EventData`` form) that JSON-lines
    ingestion never produces.
    """
    replay_dir = tmp_path / "replay_direct"
    out = replay_dir / "events"
    out.mkdir(parents=True, exist_ok=True)
    table = pa.table(
        {
            "uid": [event["uid"] for event in events],
            "time": [event["time"] for event in events],
            "class_uid": [event["class_uid"] for event in events],
            "activity_id": [event["activity_id"] for event in events],
            "log_name": [event.get("log_name", "Security") for event in events],
            "host": [event.get("host") for event in events],
            "event_json": [json.dumps(event) for event in events],
        }
    )
    pq.write_table(table, out / "fixture.parquet")
    return replay_dir


def evtx_logon(*, ip: object, uid: str) -> dict:
    """Minimal OCSF 4624 event with trimmed EVTX raw layout.

    Mirrors what the normalizer stores for ``.evtx`` rows: the typed
    endpoint is null (the ``-`` placeholder was nulled), ``LogonType``
    survives in ``unmapped``, and ``raw_data`` is the trimmed
    ``System``/``EventData`` form.
    """
    return {
        "uid": uid,
        "time": 1714658580000,
        "class_uid": 3002,
        "activity_id": 1,
        "log_name": "Security",
        "host": "web01",
        "metadata": {"uid": uid},
        "src_endpoint": None,
        "unmapped": {"LogonType": 3},
        "raw_data": json.dumps(
            {
                "System": {"EventID": 4624, "Channel": "Security"},
                "EventData": {
                    "TargetUserName": "jdoe",
                    "LogonType": 3,
                    "IpAddress": ip,
                },
            }
        ),
    }


def test_evtx_nested_placeholder_excluded_by_not_filter(tmp_path: Path) -> None:
    # The nested EVTX ``EventData.IpAddress`` of "-" must reach the
    # Sigma row exactly like the flat layout: the positive filter
    # matches the dashed row, and ``not filter`` excludes it while the
    # row with a real address is included.
    replay_dir = write_event_store(
        tmp_path,
        [evtx_logon(ip="-", uid="evtx-dash"), evtx_logon(ip="1.2.3.4", uid="evtx-ip")],
    )
    positive = make_rule(
        "evtx-positive",
        "service: security",
        "  selection:\n    IpAddress: '-'\n  condition: selection\n",
        level="medium",
    )
    matched, _, _, compiled = run_detect(replay_dir, write_rules(tmp_path, [positive]))
    assert matched[compiled[0].rule_id] == {"evtx-dash"}
    negative = make_rule(
        "evtx-negative",
        "service: security",
        "  selection:\n"
        "    EventID: 4624\n"
        "  filter:\n"
        "    IpAddress: '-'\n"
        "  condition: selection and not filter\n",
        level="medium",
    )
    matched, _, _, compiled = run_detect(replay_dir, write_rules(tmp_path, [negative]))
    assert matched[compiled[0].rule_id] == {"evtx-ip"}


def winlog_logon_record() -> dict:
    """Flat 4624 logon rewrapped in the newer winlog layout."""
    base = dict(fx.flat_security_logon(success=True))
    payload = {
        key: value
        for key, value in base.items()
        if key not in ("Channel", "EventID", "Hostname")
    }
    payload["IpAddress"] = "-"
    return {
        "winlog": {
            "channel": "Security",
            "event_id": 4624,
            "record_id": 1,
            "computer_name": "web01.example.com",
            "event_data": payload,
        },
        "@timestamp": fx.SYS_UTC,
    }


def old_beat_logon_record() -> dict:
    """Flat 4624 logon rewrapped in the older winlogbeat layout."""
    base = dict(fx.flat_security_logon(success=True))
    payload = {
        key: value
        for key, value in base.items()
        if key not in ("Channel", "EventID", "Hostname")
    }
    payload["IpAddress"] = "-"
    return {
        "log_name": "Security",
        "event_id": 4624,
        "computer_name": "web01.example.com",
        "record_number": 2,
        "@timestamp": fx.SYS_UTC,
        "event_data": payload,
    }


def test_winlog_nested_placeholder_excluded_by_not_filter(tmp_path: Path) -> None:
    # Same exclusion as the flat layout, but the "-" arrives nested
    # under ``winlog.event_data``; the fallback must find it there.
    missing = dict(fx.flat_security_logon(success=True))
    missing.pop("IpAddress")
    missing["EventIdx"] = 109
    matched, _ = matched_event_uids(
        tmp_path,
        [winlog_logon_record(), missing],
        make_rule(
            "winlog-placeholder",
            "service: security",
            "  selection:\n"
            "    EventID: 4624\n"
            "  filter:\n"
            "    IpAddress: '-'\n"
            "  condition: selection and not filter\n",
            level="medium",
        ),
    )
    assert len(matched) == 1


def test_old_beat_nested_placeholder_excluded_by_not_filter(tmp_path: Path) -> None:
    # Same exclusion as the flat layout, but the "-" arrives nested
    # under ``event_data`` in the older winlogbeat layout.
    missing = dict(fx.flat_security_logon(success=True))
    missing.pop("IpAddress")
    missing["EventIdx"] = 110
    matched, _ = matched_event_uids(
        tmp_path,
        [old_beat_logon_record(), missing],
        make_rule(
            "old-beat-placeholder",
            "service: security",
            "  selection:\n"
            "    EventID: 4624\n"
            "  filter:\n"
            "    IpAddress: '-'\n"
            "  condition: selection and not filter\n",
            level="medium",
        ),
    )
    assert len(matched) == 1


def test_absent_field_satisfies_not_filter(tmp_path: Path) -> None:
    # ``ParentImage`` is absent from both the typed event and the raw
    # record here (the key is dropped), so ``NOT`` over it is true
    # and the row is included.
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record(ParentImage=None, EventIdx=206)],
        make_rule(
            "absent",
            PROC_LOGSOURCE,
            "  selection:\n"
            "    Image|contains: '.exe'\n"
            "  filter:\n"
            "    ParentImage|contains: 'explorer'\n"
            "  condition: selection and not filter\n",
        ),
    )
    assert len(matched) == 1


def test_keyword_searches_raw_record(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [proc_record()],
        make_rule(
            "keyword",
            PROC_LOGSOURCE,
            "  selection:\n    - 'Get-Process'\n  condition: selection\n",
        ),
    )
    assert len(matched) == 1


def test_initiated_bool_matches_text_storage(tmp_path: Path) -> None:
    record = dict(fx.flat_sysmon_network())
    record["Initiated"] = "true"
    matched, _ = matched_event_uids(
        tmp_path,
        [record],
        make_rule(
            "bool",
            "category: network_connection",
            "  selection:\n"
            "    Initiated: true\n"
            "    DestinationPort: 443\n"
            "  condition: selection\n",
        ),
    )
    assert len(matched) == 1


def test_numbers_and_bools_on_text_columns(tmp_path: Path) -> None:
    matched, _ = matched_event_uids(
        tmp_path,
        [fx.flat_security_logon(success=True)],
        make_rule(
            "number",
            "service: security",
            "  selection:\n"
            "    EventID: 4624\n"
            "    LogonType: 3\n"
            "  condition: selection\n",
            level="medium",
        ),
    )
    assert len(matched) == 1


# Routing and skip-bucket tests --------------------------------------------


def test_route_logsource_covers_mapped_triples() -> None:
    assert route_logsource("windows", "process_creation", None) == "process_creation"
    assert route_logsource("windows", "process_access", None) == "process_access"
    assert route_logsource("windows", "image_load", None) == "image_load"
    assert route_logsource("windows", "file_event", None) == "file_event"
    assert (
        route_logsource("windows", "network_connection", None) == "network_connection"
    )
    assert route_logsource("windows", "registry_add", None) == "registry_add"
    assert route_logsource("windows", "registry_set", None) == "registry_set"
    assert route_logsource("windows", "registry_delete", None) == "registry_delete"
    assert route_logsource("windows", "registry_event", None) == "registry_event"
    assert route_logsource("windows", "ps_script", None) == "ps_script"
    assert route_logsource("windows", "ps_module", None) == "ps_module"
    assert route_logsource("windows", "ps_classic_start", None) == "ps_classic"
    assert route_logsource("windows", None, "powershell-classic") == "ps_classic"
    assert route_logsource("windows", None, "security") == "security"
    assert route_logsource("windows", None, "system") == "system"
    assert route_logsource("windows", None, "taskscheduler") == "taskscheduler"
    assert route_logsource("windows", "dns_query", None) is None
    assert route_logsource("windows", "pipe_created", None) is None
    assert route_logsource("windows", None, "windefend") is None
    assert route_logsource("windows", None, "sysmon") is None
    assert (
        route_logsource("linux", "process_creation", None) == "linux/process_creation"
    )


def test_experimental_status_is_skipped(tmp_path: Path) -> None:
    text = make_rule(
        "exp", PROC_LOGSOURCE, "  selection:\n    Image: 'x'\n  condition: selection\n"
    ).replace("status: test", "status: experimental")
    compiled, stats = load_rules(write_rules(tmp_path, [text]))
    assert compiled == []
    assert stats.skipped == {"status": 1}
    assert stats.skip_details == {"status": {"experimental": 1}}


def test_unmapped_logsource_is_counted(tmp_path: Path) -> None:
    compiled, stats = load_rules(
        write_rules(
            tmp_path,
            [
                make_rule(
                    "dns",
                    "category: dns_query",
                    "  selection:\n"
                    "    QueryName: 'example.com'\n"
                    "  condition: selection\n",
                )
            ],
        )
    )
    assert compiled == []
    assert stats.skipped == {"logsource": 1}
    detail = next(iter(stats.skip_details["logsource"]))
    assert "dns_query" in detail


def test_unmapped_event_id_is_counted(tmp_path: Path) -> None:
    compiled, stats = load_rules(
        write_rules(
            tmp_path,
            [
                make_rule(
                    "eid",
                    "service: security",
                    "  selection:\n    EventID: 4663\n  condition: selection\n",
                )
            ],
        )
    )
    assert compiled == []
    assert stats.skipped == {"event_id": 1}


def test_unmapped_field_is_counted_with_the_field_name(tmp_path: Path) -> None:
    compiled, stats = load_rules(
        write_rules(
            tmp_path,
            [
                make_rule(
                    "cmd",
                    IMG_LOGSOURCE,
                    "  selection:\n    CommandLine: 'x'\n  condition: selection\n",
                ),
                make_rule(
                    "eid",
                    "category: registry_event",
                    "  selection:\n    EventID: 13\n  condition: selection\n",
                ),
            ],
        )
    )
    assert compiled == []
    assert stats.skipped == {"unmapped_field": 2}
    details = stats.skip_details["unmapped_field"]
    assert details.get("image_load CommandLine") == 1
    assert details.get("registry_event EventID") == 1


def test_unsupported_modifier_is_counted(tmp_path: Path) -> None:
    compiled, stats = load_rules(
        write_rules(
            tmp_path,
            [
                make_rule(
                    "near",
                    PROC_LOGSOURCE,
                    "  selection:\n    Image: 'x'\n"
                    "  other:\n    CommandLine: 'y'\n"
                    "  condition: selection near other\n",
                )
            ],
        )
    )
    assert compiled == []
    assert stats.skipped == {"unsupported_construct": 1}


# Finding tests -------------------------------------------------------------


def _matched_info(uid: str = "event-uid-1") -> MatchedEvent:
    return MatchedEvent(
        uid=uid,
        time=1714658580000,
        class_uid=1007,
        activity_id=1,
        host="web01",
        device={"hostname": "web01.example.com"},
        actor={"user": {"name": "jdoe", "domain": "EXAMPLE"}},
        process={"pid": 1234, "name": "powershell.exe"},
        file={"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        src_endpoint=None,
        dst_endpoint=None,
    )


def _compiled_rule(**overrides: object) -> CompiledRule:
    params: dict[str, object] = {
        "rule_id": "11111111-1111-4111-8111-111111111111",
        "title": "Probe rule",
        "description": "Probe description.",
        "author": "Probe Author",
        "level": "high",
        "tags": [("attack", "t1059.001"), ("attack", "execution")],
        "references": ["https://example.com/ref"],
        "group": "process_creation",
        "sql": "SELECT * FROM slice WHERE 1 = 1",
        "source_file": "proc/rule.yml",
        "rel_path": "process_creation/rule.yml",
    }
    params.update(overrides)
    return CompiledRule(**params)  # type: ignore[arg-type]


def test_finding_uid_is_deterministic() -> None:
    assert finding_uid("rule-1", "event-1") == finding_uid("rule-1", "event-1")
    assert finding_uid("rule-1", "event-1") != finding_uid("rule-1", "event-2")
    assert finding_uid("rule-1", "event-1") != finding_uid("rule-2", "event-1")


def test_build_finding_typed_fields() -> None:
    attack = attack_fixture()
    finding = build_finding(_compiled_rule(), _matched_info(), attack, "20.0")
    assert finding.class_uid == 2004
    assert finding.severity_id == 4
    assert finding.severity == "High"
    assert finding.status == "New"
    assert finding.status_id == 1
    assert finding.start_time == finding.time == finding.end_time == 1714658580000
    assert finding.metadata is not None and finding.metadata.uid == finding_uid(
        "11111111-1111-4111-8111-111111111111", "event-uid-1"
    )
    assert finding.finding_info is not None
    assert finding.finding_info.title == "Probe rule"
    assert finding.finding_info.uid == finding.metadata.uid
    assert finding.finding_info.analytic is not None
    assert finding.finding_info.analytic.type_id == 1
    assert finding.finding_info.analytic.type == "Rule"
    assert finding.finding_info.analytic.uid == "11111111-1111-4111-8111-111111111111"
    related = finding.finding_info.related_events or []
    assert [(item.uid, item.type_uid) for item in related] == [("event-uid-1", 100701)]
    assert finding.unmapped.get("sigma_author") == "Probe Author"
    assert finding.finding_info.src_url == (
        "https://github.com/SigmaHQ/sigma/blob/r2026-07-01/"
        "rules/windows/process_creation/rule.yml"
    )
    assert finding.device is not None and finding.device.hostname == "web01.example.com"
    assert finding.metadata is not None and finding.metadata.product is not None
    assert finding.metadata.product.vendor_name == "Ekos Cyber Labs"
    # The 2004 finding itself carries no actor or endpoints; the
    # matched event's context lives in one evidences entry.
    assert finding.actor is None
    assert finding.src_endpoint is None
    assert finding.dst_endpoint is None
    assert finding.finding_info is not None
    assert not hasattr(finding.finding_info, "evidences")
    evidences = finding.evidences or []
    assert len(evidences) == 1
    assert evidences[0].uid == "event-uid-1"
    assert evidences[0].actor is not None and evidences[0].actor.user is not None
    assert evidences[0].actor.user.name == "jdoe"
    assert evidences[0].process is not None and evidences[0].process.pid == 1234
    assert evidences[0].file is not None and evidences[0].file.path is not None
    assert evidences[0].device is not None
    assert evidences[0].device.hostname == "web01.example.com"
    assert evidences[0].src_endpoint is None
    assert finding.entity_keys.host == "web01"


def test_attacks_resolve_revoked_and_drop_unknown() -> None:
    attack = attack_fixture()
    attacks, dropped = attacks_for_tags(
        attack,
        [
            ("attack", "t1059.001"),
            ("attack", "execution"),
            ("attack", "t1145"),
            ("attack", "t1065"),
            ("attack", "t9999"),
            ("attack", "not-a-tactic"),
            ("car", "car-1"),
        ],
        "20.0",
    )
    by_id = {(item.technique.uid if item.technique else None): item for item in attacks}
    assert dropped == 3
    sub = by_id["T1059"]
    assert sub.sub_technique is not None and sub.sub_technique.uid == "T1059.001"
    assert sub.tactic is not None and sub.tactic.uid == "TA9001"
    assert sub.tactic.name == "Execution"
    assert sub.version == "20.0"
    revoked = by_id["T1552"]
    assert (
        revoked.sub_technique is not None and revoked.sub_technique.uid == "T1552.004"
    )
    # The execution tactic-only entry is covered by the T1059 entry
    # carrying a technique, so it is dropped: no tactic-only entry.
    assert [item for item in attacks if item.technique is None] == []


def test_tactic_only_entry_kept_when_no_technique_covers_it() -> None:
    attack = attack_fixture()
    attacks, dropped = attacks_for_tags(
        attack,
        [("attack", "t1059.001"), ("attack", "credential-access")],
        "20.0",
    )
    assert dropped == 0
    tactic_only = [item for item in attacks if item.technique is None]
    assert len(tactic_only) == 1
    assert tactic_only[0].tactic is not None
    assert tactic_only[0].tactic.uid == "TA9002"
    assert tactic_only[0].tactic.name == "Credential Access"


def test_severity_ids_cover_sigma_levels() -> None:
    attack = attack_fixture()
    for level, severity_id in (
        ("informational", 1),
        ("low", 2),
        ("medium", 3),
        ("high", 4),
        ("critical", 5),
    ):
        finding = build_finding(
            _compiled_rule(level=level), _matched_info(), attack, "20.0"
        )
        assert finding.severity_id == severity_id


# Extractor tests ------------------------------------------------------------


def test_extract_row_reads_typed_and_unmapped(tmp_path: Path) -> None:
    from corvus.adapters.replay.schema import events_dir

    store_records = [proc_record()]
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    archive = data_dir / "events.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "events.json", "\n".join(json.dumps(record) for record in store_records)
        )
    replay_dir = tmp_path / "replay"
    load_path(archive, replay_dir=replay_dir, data_dir=data_dir)
    rows = pq.read_table(events_dir(replay_dir)).to_pylist()
    assert len(rows) == 1
    event = json.loads(rows[0]["event_json"])
    row = extract_row(event, GROUPS["process_creation"])
    assert row["Image"] == (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert row["CommandLine"] == "powershell.exe -NoProfile -Command Get-Process"
    assert row["ParentImage"] == "C:\\Windows\\explorer.exe"
    assert row["ParentCommandLine"] == "C:\\Windows\\explorer.exe"
    assert row["User"] == "EXAMPLE\\jdoe"
    assert row["EventID"] == "1"
    assert row["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert row["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert row["__fulltext"] == event["raw_data"]


def test_registry_target_reads_previous_path_on_rename() -> None:
    rename = {
        "class_uid": 201001,
        "activity_id": 5,
        "reg_key": {"path": "HKLM\\New"},
        "prev_reg_key": {"path": "HKLM\\Old"},
        "unmapped": {"TargetObject": "HKLM\\Old"},
    }
    assert mapping_mod.registry_target(rename) == "HKLM\\Old"  # type: ignore[arg-type]
    create = {
        "class_uid": 201001,
        "activity_id": 1,
        "reg_key": {"path": "HKLM\\New"},
        "unmapped": {},
    }
    assert mapping_mod.registry_target(create) == "HKLM\\New"  # type: ignore[arg-type]
    assert mapping_mod.rename_new_name(rename) == "HKLM\\New"  # type: ignore[arg-type]
    assert mapping_mod.rename_new_name(create) is None  # type: ignore[arg-type]


def test_granted_access_renders_hex_for_sigma() -> None:
    assert mapping_mod._granted_access_hex({"actual_permissions": 0x1438}) == "0x1438"  # type: ignore[arg-type]
    assert mapping_mod._granted_access_hex({}) is None  # type: ignore[arg-type]


def test_hashes_reconstruction_matches_raw_pair_form() -> None:
    event = {
        "module": {
            "file": {
                "hashes": [
                    {"algorithm_id": 3, "algorithm": "SHA-256", "value": "abc"},
                    {"algorithm_id": 18, "algorithm": "Imphash", "value": "def"},
                ]
            }
        }
    }
    assert mapping_mod.hashes_sysmon_form(event) == "SHA256=abc,IMPHASH=def"  # type: ignore[arg-type]


# Store round-trip and CLI tests ----------------------------------------------


def test_write_findings_is_deterministic(tmp_path: Path) -> None:
    from corvus.adapters.replay.findings import write_findings

    attack = attack_fixture()
    replay_dir = write_store(tmp_path, [proc_record(), fx.flat_sysmon_network()])
    rules_dir = write_rules(
        tmp_path,
        [
            make_rule(
                "image",
                PROC_LOGSOURCE,
                "  selection:\n"
                "    Image|contains: 'powershell'\n"
                "  condition: selection\n",
            )
        ],
    )
    compiled, _ = load_rules(rules_dir)
    assert len(compiled) == 1
    matches, infos, _ = evaluate(replay_dir, compiled)
    first = write_findings(replay_dir, compiled, matches, infos, attack, "20.0")
    assert first.findings == 1
    assert first.files == 1
    before = sorted(
        (path.name, path.read_bytes())
        for path in findings_dir(replay_dir).glob("*.parquet")
    )
    second = write_findings(replay_dir, compiled, matches, infos, attack, "20.0")
    assert second.findings == first.findings
    after = sorted(
        (path.name, path.read_bytes())
        for path in findings_dir(replay_dir).glob("*.parquet")
    )
    assert [name for name, _ in before] == [name for name, _ in after]
    table = pq.read_table(findings_dir(replay_dir))
    assert table.schema.names == [
        "uid",
        "time",
        "class_uid",
        "rule_id",
        "level",
        "host",
        "finding_json",
    ]
    row = table.to_pylist()[0]
    assert row["class_uid"] == 2004
    assert row["level"] == "high"
    assert row["host"] == "web01"
    finding = json.loads(row["finding_json"])
    assert finding["finding_info"]["related_events"][0]["uid"] != row["uid"]
    assert finding["finding_info"]["uid"] == row["uid"]
    assert finding["unmapped"]["sigma_author"] == "Probe Author"


def test_cli_detect_writes_findings(tmp_path: Path) -> None:
    from corvus.cli import main

    attack_path = tmp_path / "attack.json"
    attack_path.write_text(
        json.dumps(
            {
                "attack_version": "v20.0",
                "tactics": {"execution": {"name": "Execution", "id": "TA9001"}},
                "tactic_order": ["execution"],
                "techniques": {
                    "T1059.001": {
                        "name": "PowerShell",
                        "tactics": ["execution"],
                        "is_subtechnique": True,
                        "parent": "T1059",
                        "deprecated": False,
                        "revoked": False,
                        "revoked_by": None,
                    },
                    "T1059": {
                        "name": "Command and Scripting Interpreter",
                        "tactics": ["execution"],
                        "is_subtechnique": False,
                        "parent": None,
                        "deprecated": False,
                        "revoked": False,
                        "revoked_by": None,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    replay_dir = write_store(tmp_path, [proc_record()])
    rules_dir = write_rules(
        tmp_path,
        [
            make_rule(
                "image",
                PROC_LOGSOURCE,
                "  selection:\n"
                "    Image|contains: 'powershell'\n"
                "  condition: selection\n",
            )
        ],
    )
    assert (
        main(
            [
                "replay",
                "detect",
                "--rules-dir",
                str(rules_dir),
                "--replay-dir",
                str(replay_dir),
                "--attack",
                str(attack_path),
            ]
        )
        == 0
    )
    assert len(list(findings_dir(replay_dir).glob("*.parquet"))) == 1


# Linux routing unit tests -------------------------------------------------


def test_linux_logsource_routes_to_linux_groups() -> None:
    assert (
        route_logsource("linux", "process_creation", None) == "linux/process_creation"
    )
    assert route_logsource("linux", "file_event", None) == "linux/file_event"
    assert (
        route_logsource("linux", "network_connection", None)
        == "linux/network_connection"
    )


def test_linux_out_of_scope_shapes_stay_unrouted() -> None:
    assert route_logsource("linux", None, "auditd") is None
    assert route_logsource("linux", None, "sshd") is None
    assert route_logsource("linux", None, "syslog") is None
    assert route_logsource("linux", None, "cron") is None
    assert route_logsource("linux", None, None) is None
    assert route_logsource("linux", "process_creation", "auditd") is None


def test_linux_process_row_reads_typed_slots() -> None:
    group = mapping_mod.GROUPS["linux/process_creation"]
    event = {
        "process": {"file": {"path": "/usr/bin/find"}, "cmd_line": "find /x -exec"},
        "actor": {"user": {"name": "deploy"}},
        "raw_data": "{}",
    }
    row = mapping_mod.extract_row(event, group, need_fulltext=False)
    assert row["Image"] == "/usr/bin/find"
    assert row["CommandLine"] == "find /x -exec"
    assert row["User"] == "deploy"


def test_linux_unmapped_fields_skip_with_field_name(tmp_path: Path) -> None:
    rule = """title: Linux parent probe
id: 44444444-4444-4433-8444-444444444444
status: test
description: Probe rule for tests.
author: Probe Author
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage: '/usr/bin/bash'
  condition: selection
level: high
"""
    rules_dir = write_rules(tmp_path, [rule])
    compiled, stats = load_rules(rules_dir)
    assert compiled == []
    assert stats.skip_details["unmapped_field"] == {
        "linux/process_creation ParentImage": 1
    }
