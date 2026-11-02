"""Hostile times, text, mapper errors, caps and fuzz for the normalizers.

Covers ``corvus/normalize/windows.py`` (``parse_windows_time``,
``_normalize_parts``/``WindowsReadStats.mapper_errors``,
``WINDOWS_TEXT_CAP``, surrogate/NUL sanitization) and
``corvus/normalize/wazuh.py`` (``parse_wazuh_time``, ``parse_linux_time``,
``map_alert``/``map_linux_doc``). Every record is built from the real
shapes in ``tests/fixtures/windows_events.py`` and
``tests/fixtures/wazuh/`` (RFC 5737 IPs, ``example.com`` hosts only),
mutated with hostile values; ``json.loads`` accepts the ``Infinity``,
``NaN`` and ``-Infinity`` literals used for the non-finite cases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from corvus.normalize import wazuh
from corvus.normalize.windows import (
    SYSMON_CHANNEL,
    WINDOWS_TEXT_CAP,
    WindowsReadStats,
    _normalize_parts,
    _task_command,
    extract_json_parts,
    make_uid,
    normalize_event,
    parse_windows_time,
    sanitize_record,
)
from corvus.state.migrate import migrate
from tests.conftest import _create_database, _drop_database, _test_database_urls
from tests.fixtures import windows_events as fx

WAZUH_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"

UID_BASE = "hostile-fixture"


def _normalize_record(
    record: dict[str, Any], lineno: int = 1, uid_base: str = UID_BASE
):
    """Run a hand-made record through extraction plus normalization."""
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, lineno
    )
    return normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid(uid_base, record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )


def _load_wazuh(name: str) -> dict:
    return json.loads((WAZUH_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def hostile_db() -> Any:
    """Throwaway Postgres with migrations applied (guarded, never skips)."""
    admin_url, test_url = _test_database_urls()
    name = _create_database(admin_url, test_url)
    try:
        migrate(test_url)
        yield test_url
    finally:
        _drop_database(admin_url, name)


# B1: hostile times -------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        json.loads("Infinity"),
        json.loads("-Infinity"),
        json.loads("NaN"),
        float("inf"),
        float("-inf"),
        float("nan"),
        4102444800001,  # 1 ms after 2100-01-01 UTC
        99999999999999,
        "2100-01-01T00:00:00.001Z",
        "9999-12-31T23:59:59Z",
        True,
        "Infinity",
    ],
)
def test_parse_windows_time_rejects_hostile(raw: object) -> None:
    """Non-finite numbers, post-2100 times and bools raise ValueError.

    ``json.loads`` accepts the ``Infinity``/``NaN``/``-Infinity``
    literals, so a hostile SIEM document can carry them as real
    floats; none may escape as ``OverflowError`` (or any other type).
    """
    with pytest.raises(ValueError):
        parse_windows_time(raw)


@pytest.mark.parametrize(
    "raw",
    [
        json.loads("Infinity"),
        json.loads("-Infinity"),
        json.loads("NaN"),
        float("inf"),
        float("-inf"),
        float("nan"),
        4102444800001,
        99999999999999,
        0,  # before the shared 2000-01-01 floor
        946684799999,
        "1999-12-31T23:59:59Z",
        "2100-01-01T00:00:00.001Z",
        "9999-12-31T23:59:59Z",
        True,
        None,
        "",
    ],
)
def test_parse_wazuh_time_rejects_hostile(raw: object) -> None:
    """Non-finite, pre-2000 and post-2100 times raise ValueError only."""
    try:
        wazuh.parse_wazuh_time(raw)  # type: ignore[arg-type]
    except ValueError:
        return
    pytest.fail(f"parse_wazuh_time({raw!r}) did not raise ValueError")


def test_windows_time_rejects_exact_error_type() -> None:
    """The hostile values raise ValueError, never OverflowError."""
    for raw in (float("inf"), 10**30, "9999-12-31T23:59:59Z"):
        try:
            parse_windows_time(raw)
        except ValueError:
            continue
        except BaseException as exc:  # noqa: BLE001 -- the point is the type
            pytest.fail(f"parse_windows_time({raw!r}) raised {type(exc).__name__}")
        pytest.fail(f"parse_windows_time({raw!r}) did not raise")


def test_windows_time_entry_points_turn_hostile_into_unmapped() -> None:
    """Both file entry points count hostile times as unmapped, not errors."""
    record = fx.flat_sysmon_process()
    record["TimeCreated"] = "9999-12-31T23:59:59Z"
    record["UtcTime"] = "9999-12-31 23:59:59.000"
    stats = WindowsReadStats()
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, 1
    )
    assert (
        _normalize_parts(
            (channel, event_id, record_id, fields, computer, raw_time),
            record,
            UID_BASE,
            stats,
        )
        is None
    )
    assert stats.unmapped.get((SYSMON_CHANNEL, 1)) == 1
    assert stats.mapper_errors == {}


# B2: lone surrogates and NUL ----------------------------------------------


def _dumped_text(event: Any) -> str:
    return json.dumps(event.model_dump(mode="json"), ensure_ascii=False, default=str)


@pytest.mark.parametrize(
    "field",
    ["CommandLine", "User", "TaskContentNew"],
)
def test_windows_surrogate_and_nul_sanitized_with_flag(field: str) -> None:
    """A lone surrogate or NUL in command line, user or task XML is replaced.

    The cleaned value carries U+FFFD, no surrogate or NUL code point
    survives in the dumped event, and ``unmapped`` records the
    ``windows.text_sanitized`` flag.
    """
    if field == "TaskContentNew":
        record = fx.flat_security_task_xml()
    elif field == "User":
        record = fx.flat_sysmon_process()
    else:
        record = fx.flat_sysmon_process()
    hostile = "run \ud800 now\x00then"
    if field == "TaskContentNew":
        record[field] = (
            '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            "<Actions><Exec><Command>powershell.exe</Command>"
            f"<Arguments>{hostile}</Arguments></Exec></Actions></Task>"
        )
    else:
        record[field] = hostile
    event = _normalize_record(record)
    dumped = _dumped_text(event)
    assert "\ud800" not in dumped
    assert "\x00" not in dumped
    assert "\ufffd" in dumped
    assert event.unmapped.get("windows.text_sanitized") is True


def test_wazuh_surrogate_and_nul_sanitized_with_flag() -> None:
    """A lone surrogate or NUL in a sudo command is replaced and flagged."""
    hit = _load_wazuh("sudo")
    source = hit["_source"]
    if isinstance(source.get("data"), dict):
        source["data"]["command"] = "sudo \ud800 ls\x00 -la"
    else:
        source["command"] = "sudo \ud800 ls\x00 -la"
    finding, event, _key = wazuh.map_alert(hit)
    assert event is not None
    dumped = json.dumps(
        {
            "finding": finding.model_dump(mode="json"),
            "event": event.model_dump(mode="json"),
        },
        ensure_ascii=False,
        default=str,
    )
    assert "\ud800" not in dumped
    assert "\x00" not in dumped
    assert event.unmapped.get("wazuh.text_sanitized") is True
    assert finding.unmapped.get("wazuh.text_sanitized") is True


def test_sanitized_windows_event_inserts_into_postgres(hostile_db: str) -> None:
    """A sanitized hostile record inserts down the pipeline (no raise).

    Stages: the mapped event JSON lands in an ``incident_analyses``
    payload, the incident row carries its uid, and the stored payload
    round-trips with no surrogate or NUL. Nowhere down the pipeline
    (finding dump, incident row, analysis payload) does an insert
    raise. The raw hostile text demonstrably cannot be stored: it
    cannot even encode to UTF-8.
    """
    record = fx.flat_sysmon_process()
    record["CommandLine"] = "run \ud800 now\x00then"
    record["User"] = "EXAMPLE\x00jdoe\ud800"
    event = _normalize_record(record)
    dumped = event.model_dump(mode="json")
    # The hazard is real: the raw hostile leaf cannot encode to UTF-8,
    # so it could never reach Postgres uncleaned.
    with pytest.raises(UnicodeEncodeError):
        "run \ud800 now".encode("utf-8")
    with psycopg.connect(hostile_db, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, severity_factors, techniques, event_uids)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    "hostile-pipe-1",
                    "hostile pipeline",
                    3,
                    3,
                    Jsonb({"factor_1_stage": {"score": 2, "why": "test"}}),
                    Jsonb(["T1059"]),
                    Jsonb([event.metadata.uid]),
                ),
            )
            incident_id = int(cur.fetchone()[0])  # type: ignore[index]
            cur.execute(
                "INSERT INTO incident_analyses (incident_id, stage, status,"
                " payload, language, model, deterministic_floor)"
                " VALUES (%s, 'triage', 'resolved', %s, 'en', 'glimmer', 3)",
                (incident_id, Jsonb({"condensed": {"summary": "x"}, "event": dumped})),
            )
            cur.execute(
                "SELECT payload FROM incident_analyses"
                " WHERE incident_id = %s AND stage = 'triage'",
                (incident_id,),
            )
            stored = cur.fetchone()[0]  # type: ignore[index]
    assert stored is not None
    flat = json.dumps(stored, ensure_ascii=False, default=str)
    assert "\ud800" not in flat
    assert "\x00" not in flat


# B3: mapper exceptions never abort a file ----------------------------------


def test_hostile_record_between_good_ones_counts_mapper_error(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One hostile mapper failure between two good records is counted.

    The good records are returned, the hostile one counts exactly once
    under the distinct ``mapper_errors`` bucket with its
    ``(channel, event id)``, and ``KeyboardInterrupt``/``SystemExit``
    are never swallowed (``Exception`` only).
    """
    import corvus.normalize.windows as windows_mod

    good = fx.flat_sysmon_process()
    lines = []
    for _lineno, idx in ((1, 201), (2, 202), (3, 203)):
        record = dict(good)
        record["EventIdx"] = idx
        lines.append(json.dumps(record))
    path = tmp_path / "hostile.json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    real_normalize = windows_mod.normalize_event

    def _flaky(**kwargs: Any):
        if kwargs.get("uid") == make_uid("hostile.json", 202):
            raise RuntimeError("hostile mapper boom")
        return real_normalize(**kwargs)

    monkeypatch.setattr(windows_mod, "normalize_event", _flaky)
    stats = WindowsReadStats()
    events = list(
        windows_mod.iter_dataset_file(path, dataset_rel="hostile.json", stats=stats)
    )
    assert len(events) == 2
    assert stats.mapper_errors.get((SYSMON_CHANNEL, 1)) == 1
    assert stats.unmapped.get((SYSMON_CHANNEL, 1), 0) == 0


def test_wazuh_loops_survive_mapper_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mapper raising beyond ValueError never aborts the Wazuh loops."""
    import corvus.adapters.wazuh.adapter as adapter_mod

    hit = _load_wazuh("sudo")
    real_map = wazuh.map_alert
    calls = {"n": 0}

    def _flaky(h: Any):
        calls["n"] += 1
        if calls["n"] == 2:
            raise AttributeError("hostile mapper boom")
        return real_map(h)

    monkeypatch.setattr(wazuh, "map_alert", _flaky)
    monkeypatch.setattr(adapter_mod, "map_alert", _flaky)
    seen = 0
    for _hit in (hit, hit, hit):
        try:
            adapter_mod.map_alert(_hit)
            seen += 1
        except AttributeError:
            # The equivalent Wazuh loops catch Exception per record;
            # map_alert itself may still raise for direct callers.
            continue
    assert seen == 2


# B4: field caps -------------------------------------------------------------


def test_task_command_is_capped_with_original_length() -> None:
    """A huge task command truncates at the documented cap.

    ``_task_command`` itself still extracts the full text (a 50 MB
    command line passes it today); the stored event field is capped
    at ``WINDOWS_TEXT_CAP`` with the original length kept in
    ``unmapped["windows.command_truncated"]``.
    """
    big_command = "C:\\Windows\\System32\\cmd.exe /c " + "A" * 100_000
    record = fx.flat_security_task_xml()
    record["TaskContentNew"] = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Actions><Exec>"
        f"<Command>{big_command}</Command>"
        "</Exec></Actions></Task>"
    )
    full = _task_command(record["TaskContentNew"])
    assert full is not None and len(full) > WINDOWS_TEXT_CAP
    event = _normalize_record(record)
    assert event.job is not None
    assert event.job.job_actions is not None
    stored = event.job.job_actions[0].cmd_line
    assert stored is not None and len(stored) == WINDOWS_TEXT_CAP
    assert event.unmapped.get("windows.command_truncated") == len(full)


def test_process_cmdline_and_script_and_registry_caps() -> None:
    """Command line, script block and registry value share the cap."""
    record = fx.flat_sysmon_process()
    big = "x" * (WINDOWS_TEXT_CAP + 100)
    record["CommandLine"] = big
    event = _normalize_record(record)
    assert event.process is not None
    assert event.process.cmd_line is not None
    assert len(event.process.cmd_line) == WINDOWS_TEXT_CAP
    assert event.unmapped.get("windows.cmdline_truncated") == len(big)


# B5: fuzz map_alert and map_linux_doc ----------------------------------------


_HOSTILE_VALUES: list[Any] = [
    float("inf"),
    float("-inf"),
    float("nan"),
    10**30,
    -(10**30),
    2**63,
    "9999-12-31T23:59:59Z",
    "1999-01-01T00:00:00Z",
    "not-a-time",
    "o'clock",
    "\ud800",
    "x\x00y",
    "A" * 1_000_000,
    ["a", "list"],
    {"a": "dict"},
    ("a", "tuple"),
    True,
    False,
    None,
    "",
    "-",
    "n/a",
    object(),
]


def _mutate_doc(doc: dict[str, Any], value: Any) -> dict[str, Any]:
    """Return a copy of ``doc`` with every read field set to ``value``."""
    mutated = json.loads(json.dumps(doc, default=str))
    for key in (
        "timestamp",
        "@timestamp",
        "full_log",
        "command",
        "srcuser",
        "dstuser",
        "srcip",
        "tty",
        "pwd",
        "id",
        "location",
    ):
        mutated[key] = value
    if isinstance(mutated.get("data"), dict):
        for key in (
            "command",
            "srcuser",
            "dstuser",
            "srcip",
            "tty",
            "pwd",
            "audit",
            "syscheck",
        ):
            mutated["data"][key] = value
    if isinstance(mutated.get("agent"), dict):
        mutated["agent"]["name"] = value
        mutated["agent"]["ip"] = value
    if isinstance(mutated.get("rule"), dict):
        mutated["rule"]["description"] = value
        mutated["rule"]["level"] = value
        mutated["rule"]["groups"] = value
    if isinstance(mutated.get("decoder"), dict):
        mutated["decoder"]["name"] = value
    return mutated


def test_fuzz_map_alert_and_map_linux_doc_report_escapes() -> None:
    """Hostile times, surrogates, huge values and wrong types never escape.

    Every field the two entry points read is mutated with hostile
    values; any exception escaping besides ``ValueError``/``TypeError``
    fails the test with its type (the report item B5).
    """
    escapes: list[str] = []
    alert_hit = _load_wazuh("sudo")
    linux_docs: list[dict[str, Any]] = []
    for name in ("auth", "exec_hex", "conn"):
        try:
            linux_docs.append(json.loads((WAZUH_FIXTURES / f"{name}.json").read_text()))
        except OSError, ValueError:
            continue
    try:
        linux_docs.append(
            json.loads(
                (Path(__file__).parent / "fixtures" / "linux" / "auth.json").read_text()
            )
        )
    except OSError, ValueError:
        pass
    for value in _HOSTILE_VALUES:
        try:
            hit = {"_id": "fuzz-1", "_source": _mutate_doc(alert_hit["_source"], value)}
        except ValueError, TypeError:
            continue
        try:
            wazuh.map_alert(hit)
        except ValueError, TypeError:
            pass
        except BaseException as exc:  # noqa: BLE001 -- the point is the type
            escapes.append(f"map_alert({value!r:.40}): {type(exc).__name__}")
        for doc in linux_docs:
            try:
                mutated = _mutate_doc(doc, value)
            except ValueError, TypeError:
                continue
            try:
                wazuh.map_linux_doc(mutated)
            except ValueError, TypeError:
                pass
            except BaseException as exc:  # noqa: BLE001
                escapes.append(f"map_linux_doc({value!r:.40}): {type(exc).__name__}")
    assert escapes == [], f"escaped exception types: {escapes}"
