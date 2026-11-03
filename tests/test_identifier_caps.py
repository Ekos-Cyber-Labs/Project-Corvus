"""Identifier caps: every source id reaching a typed OCSF slot is bounded.

Prompt 34 capped every leftover ``unmapped`` value, the ``raw_data``
leaves and the MITRE names/ids, but three source paths still pass
through whole into typed slots: the alert ``id`` (event
``metadata.uid``, finding ``metadata.uid`` / ``finding_info.uid`` and
the evidence/related-event uids), ``rule.id`` (the analytic ``uid``)
and ``decoder.name`` (both metadata ``log_name`` slots). The archive
document ``_id`` reaches the event ``uid`` through the same sink.

An identifier stays unique and deterministic after the cap: values
within the cap are byte-identical, longer values keep their first
characters plus a short hash of the full value, and the original
length lands in ``unmapped["<key>_truncated"]``.

``probe_oversize_ocsf_paths`` is the reviewer-style probe: it sets
every node of every Wazuh and Windows fixture to a hostile value, maps
the record, and reports any typed value (``raw_data`` excluded) over
the cap. Each leaf is probed with one hostile kind, rotating
str/list/dict across leaves, and fixtures whose leaf set repeats an
earlier one are skipped, so the probe stays under a minute. The known
identifier source paths are always probed with the hostile string.
"""

from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
from typing import Any

from corvus.normalize import wazuh
from corvus.normalize import windows as win
from corvus.normalize.ocsf import ENTITY_KEY_CAP, compute_entity_keys
from corvus.normalize.wazuh import WAZUH_RAW_DATA_CAP, WAZUH_UNMAPPED_LIST_CAP
from corvus.normalize.windows import (
    WINDOWS_TEXT_CAP,
    WINDOWS_UNMAPPED_LIST_CAP,
    extract_json_parts,
    make_uid,
    normalize_event,
    sanitize_record,
)
from tests.fixtures import windows_events as fx

WAZUH_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"
LINUX_FIXTURES = Path(__file__).parent / "fixtures" / "linux"
LIVE_FIXTURES = Path(__file__).parent / "fixtures" / "wazuh_live"

CAP = 65536
LIST_CAP = 1000
#: Hostile values just over the caps: the string exceeds CAP, and the
#: 1100-item containers exceed both LIST_CAP and CAP once serialized
#: (so a stringified identifier still overflows), keeping the probe fast.
HOSTILE_STR = "X" * 70000
HOSTILE_PAD = "X" * 64
HOSTILE_LIST: list[str] = [f"item-{index:05d}-{HOSTILE_PAD}" for index in range(1100)]
HOSTILE_DICT: dict[str, str] = {
    f"key-{index:05d}": f"value-{index:05d}-" + "Y" * 64 for index in range(1100)
}
#: One hostile kind probed per leaf, rotating across leaves.
HOSTILE_KINDS = ("str", "list", "dict")
#: Identifier source paths always probed with the hostile string, so a
#: removed identifier cap fails the probe whatever the rotation lands on.
ALERT_STR_PATHS = frozenset(
    {("id",), ("rule", "id"), ("decoder", "name"), ("decoder",)}
)
LINUX_STR_PATHS = frozenset({("id",), ("rule", "id")})


def _hostile(kind: str) -> Any:
    """Return a fresh hostile value of one kind (templates stay shared)."""
    if kind == "str":
        return HOSTILE_STR
    if kind == "list":
        return copy.deepcopy(HOSTILE_LIST)
    return copy.deepcopy(HOSTILE_DICT)


def _iter_paths(node: Any, prefix: tuple[str | int, ...] = ()) -> Any:
    """Yield every (path, value) pair below ``node``, containers included."""
    if isinstance(node, dict):
        for key, value in node.items():
            path = prefix + (key,)
            yield path, value
            yield from _iter_paths(value, path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            path = prefix + (index,)
            yield path, value
            yield from _iter_paths(value, path)


def _set_path(doc: Any, path: tuple[str | int, ...], value: Any) -> None:
    node = doc
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def _typed_str_sizes(obj: Any) -> list[tuple[str, int]]:
    """Return (dotted path, length) for every str leaf but ``raw_data``."""
    found: list[tuple[str, int]] = []
    stack: list[tuple[Any, str]] = [(obj.model_dump(), "")]
    while stack:
        node, prefix = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "raw_data":
                    continue
                stack.append((value, f"{prefix}.{key}" if prefix else str(key)))
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                stack.append((value, f"{prefix}[{index}]"))
        elif isinstance(node, str):
            found.append((prefix, len(node)))
    return found


def _measure(*objs: Any) -> list[tuple[str, int]]:
    sizes: list[tuple[str, int]] = []
    for obj in objs:
        if obj is not None:
            sizes.extend(_typed_str_sizes(obj))
    return sizes


def _record_path(path: tuple[str | int, ...]) -> str:
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else f".{part}"
    return out.lstrip(".")


def probe_oversize_ocsf_paths() -> list[str]:
    """Map every fixture with every node set hostile; report typed overflow.

    Returns entries of the form
    ``"<corpus>/<fixture> <hostile path>=<kind> -> <typed path> (<size>)"``
    for each typed string over the cap. An empty list means every
    identifier-like source value reaching a typed slot is bounded.
    """
    violations: list[str] = []
    counter = 0

    def check(
        corpus: str,
        name: str,
        make: Any,
        paths: list[tuple[str | int, ...]],
        force_str: frozenset[tuple[str | int, ...]] = frozenset(),
    ) -> None:
        nonlocal counter
        for path in paths:
            if path in force_str:
                kinds = ("str",)
            else:
                kinds = (HOSTILE_KINDS[counter % len(HOSTILE_KINDS)],)
                counter += 1
            for kind in kinds:
                try:
                    objs = make(_hostile(kind), path)
                except Exception:  # noqa: BLE001 - hostile input may not map
                    continue
                for typed_path, size in _measure(*objs):
                    if size > CAP:
                        violations.append(
                            f"{corpus}/{name} {_record_path(path)}={kind} "
                            f"-> {typed_path} ({size})"
                        )

    for fixture in sorted(WAZUH_FIXTURES.glob("*.json")):
        hit = json.loads(fixture.read_text(encoding="utf-8"))

        def make_alert(hostile: Any, path: Any, hit: Any = hit) -> Any:
            trial = copy.deepcopy(hit)
            _set_path(trial["_source"], path, hostile)
            finding, event, _key = wazuh.map_alert(trial)
            return (finding, event)

        alert_paths = [p for p, _ in _iter_paths(hit["_source"])]
        check("alert", fixture.name, make_alert, alert_paths, ALERT_STR_PATHS)

    for fixture in sorted(LINUX_FIXTURES.glob("*.json")):
        doc = json.loads(fixture.read_text(encoding="utf-8"))

        def make_linux(hostile: Any, path: Any, doc: Any = doc) -> Any:
            trial = copy.deepcopy(doc)
            _set_path(trial, path, hostile)
            finding, event, _key, _dedupe = wazuh.map_linux_doc(trial)
            return (finding, event)

        check(
            "linux",
            fixture.name,
            make_linux,
            [p for p, _ in _iter_paths(doc)],
            LINUX_STR_PATHS,
        )
        ruled = copy.deepcopy(doc)
        ruled["rule"] = {"id": 1, "description": "probe", "level": 3, "groups": []}

        def make_ruled(hostile: Any, path: Any, ruled: Any = ruled) -> Any:
            trial = copy.deepcopy(ruled)
            _set_path(trial, path, hostile)
            finding, event, _key, _dedupe = wazuh.map_linux_doc(trial)
            return (finding, event)

        # The ruled document repeats the plain leaf set outside ``rule``;
        # only the rule subtree is new.
        check(
            "linux-ruled",
            fixture.name,
            make_ruled,
            [p for p, _ in _iter_paths(ruled) if p and p[0] == "rule"],
            LINUX_STR_PATHS,
        )

    for fixture in sorted(LIVE_FIXTURES.glob("*.json")):
        doc = json.loads(fixture.read_text(encoding="utf-8"))
        if isinstance(doc.get("rule"), dict):

            def make_live_alert(hostile: Any, path: Any, doc: Any = doc) -> Any:
                trial = copy.deepcopy(doc)
                _set_path(trial, path, hostile)
                finding, event, _key = wazuh.map_alert(
                    {"_id": "probe", "_source": trial}
                )
                return (finding, event)

            check(
                "live-alert",
                fixture.name,
                make_live_alert,
                [p for p, _ in _iter_paths(doc)],
                ALERT_STR_PATHS,
            )
        else:

            def make_live_archive(hostile: Any, path: Any, doc: Any = doc) -> Any:
                trial = copy.deepcopy(doc)
                _set_path(trial, path, hostile)
                event, _key = wazuh.map_archive({"_id": "probe", "_source": trial})
                return (event,)

            check(
                "live-archive",
                fixture.name,
                make_live_archive,
                [p for p, _ in _iter_paths(doc)],
                ALERT_STR_PATHS,
            )

            def make_live_id(hostile: Any, _path: Any, doc: Any = doc) -> Any:
                if not isinstance(hostile, str):
                    raise ValueError("archive _id must be a string to map")
                event, _key = wazuh.map_archive(
                    {"_id": hostile, "_source": copy.deepcopy(doc)}
                )
                return (event,)

            check("live-archive", f"{fixture.name} envelope _id", make_live_id, [()])

    seen_windows: set[frozenset[str]] = set()
    for name, func in sorted(inspect.getmembers(fx, inspect.isfunction)):
        if name.startswith("_") or name == "flat_unmapped":
            continue
        try:
            made = func() if name != "flat_security_logon" else func(success=True)
        except TypeError:
            continue
        records = made if isinstance(made, list) else [made]

        def make_windows(hostile: Any, path: Any, record: Any = records[0]) -> Any:
            trial = copy.deepcopy(record)
            if path:
                _set_path(trial, path, hostile)
            else:
                trial = hostile if isinstance(hostile, dict) else trial
            channel, event_id, record_id, fields, computer, raw_time = (
                extract_json_parts(trial, 1)
            )
            return (
                normalize_event(
                    channel=channel,
                    event_id=event_id,
                    fields=sanitize_record(fields),
                    computer=computer,
                    uid=make_uid("probe", record_id),
                    raw_time=raw_time,
                    raw_record=sanitize_record(copy.deepcopy(trial)),
                ),
            )

        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            # Records repeating an earlier leaf set probe the same typed
            # slots; the hostile values replace every value, so only
            # constants (channel, event id) could differ.
            record_paths = [p for p, _ in _iter_paths(record)]
            signature = frozenset(map(repr, record_paths))
            if signature in seen_windows:
                continue
            seen_windows.add(signature)

            def make_indexed(hostile: Any, path: Any, record: Any = record) -> Any:
                return make_windows(hostile, path, record)

            check(
                "windows",
                f"{name}[{index}]",
                make_indexed,
                record_paths,
            )
    return violations


def test_probe_no_typed_ocsf_value_exceeds_cap() -> None:
    """Every fixture node set hostile leaves typed slots within the cap."""
    violations = probe_oversize_ocsf_paths()
    assert violations == [], "\n".join(violations[:40])


def _sudo_hit(**overrides: Any) -> dict[str, Any]:
    """Build a synthetic sudo alert hit (adversarial, not a fixture)."""
    hit = json.loads((WAZUH_FIXTURES / "sudo.json").read_text(encoding="utf-8"))
    source = hit["_source"]
    for key, value in overrides.items():
        source[key] = value
    return hit


def test_alert_id_over_cap_keeps_prefix_and_hash() -> None:
    """A 300KB alert id caps at the cap with its length kept (synthetic)."""
    long_id = "X" * 300_000
    finding, event, _key = wazuh.map_alert(_sudo_hit(id=long_id))
    assert event is not None
    assert finding.finding_info is not None
    assert len(finding.finding_info.uid) == CAP
    assert len(finding.metadata.uid) == CAP
    assert len(event.metadata.uid) == CAP
    assert finding.finding_info.uid is not None
    assert finding.finding_info.uid.startswith(long_id[:100])
    assert "#" in finding.finding_info.uid
    assert finding.unmapped.get("wazuh.alert_id_truncated") == len(long_id)
    assert event.unmapped.get("wazuh.event_uid_truncated") == CAP + len("#event")


def test_alert_ids_sharing_a_prefix_do_not_collide() -> None:
    """Two long ids with the same prefix cap to different uids (synthetic)."""
    first = "P" * CAP + "1"
    second = "P" * CAP + "2"
    finding_one, _, _ = wazuh.map_alert(_sudo_hit(id=first))
    finding_two, _, _ = wazuh.map_alert(_sudo_hit(id=second))
    assert finding_one.finding_info is not None
    assert finding_two.finding_info is not None
    assert finding_one.finding_info.uid != finding_two.finding_info.uid
    assert finding_one.finding_info.uid is not None
    assert finding_two.finding_info.uid is not None
    assert len(finding_one.finding_info.uid) == CAP
    assert len(finding_two.finding_info.uid) == CAP


def test_alert_id_within_cap_is_byte_identical() -> None:
    """A normal alert id reaches every uid slot unchanged."""
    hit = _sudo_hit()
    raw_id = hit["_source"]["id"]
    assert len(raw_id) < CAP
    finding, event, _key = wazuh.map_alert(hit)
    assert finding.finding_info is not None
    assert event is not None
    assert finding.finding_info.uid == raw_id
    assert finding.metadata.uid == raw_id
    assert event.metadata.uid == f"{raw_id}#event"
    assert "wazuh.alert_id_truncated" not in finding.unmapped
    assert "wazuh.event_uid_truncated" not in event.unmapped
    assert "wazuh.rule_id_truncated" not in finding.unmapped
    assert "wazuh.decoder_truncated" not in finding.unmapped
    assert "wazuh.decoder_truncated" not in event.unmapped


def test_rule_id_over_cap_is_bounded() -> None:
    """A 300KB rule id caps the analytic uid with its length kept."""
    long_rule = "R" * 300_000
    hit = _sudo_hit()
    hit["_source"]["rule"]["id"] = long_rule
    finding, _event, _key = wazuh.map_alert(hit)
    assert finding.finding_info is not None
    assert finding.finding_info.analytic is not None
    capped = finding.finding_info.analytic.uid
    assert capped is not None
    assert len(capped) == CAP
    assert capped.startswith(long_rule[:100])
    assert finding.unmapped.get("wazuh.rule_id_truncated") == len(long_rule)


def test_decoder_name_over_cap_is_bounded() -> None:
    """A 300KB decoder name caps both log_name slots with length kept."""
    long_decoder = "D" * 300_000
    hit = _sudo_hit(decoder={"name": long_decoder})
    finding, event, _key = wazuh.map_alert(hit)
    assert event is None
    assert len(finding.metadata.log_name) == CAP
    assert finding.metadata.log_name.startswith(long_decoder[:100])
    assert finding.unmapped.get("wazuh.decoder_truncated") == len(long_decoder)


def test_archive_doc_id_over_cap_is_bounded() -> None:
    """A 300KB archive _id caps the event uid with its length kept."""
    doc = json.loads((LIVE_FIXTURES / "archive_real.json").read_text(encoding="utf-8"))
    long_doc_id = "A" * 300_000
    event, _key = wazuh.map_archive({"_id": long_doc_id, "_source": doc})
    assert event is not None
    assert len(event.metadata.uid) == CAP
    assert event.metadata.uid.startswith(long_doc_id[:100])
    assert event.unmapped.get("wazuh.event_uid_truncated") == len(long_doc_id)


def test_id_list_and_dict_values_are_bounded() -> None:
    """Non-string ids stringify before the cap, never around it."""
    for hostile in (HOSTILE_LIST, HOSTILE_DICT):
        finding, event, _key = wazuh.map_alert(_sudo_hit(id=copy.deepcopy(hostile)))
        assert event is not None
        assert finding.finding_info is not None
        assert finding.finding_info.uid is not None
        assert len(finding.finding_info.uid) == CAP
        assert len(event.metadata.uid) == CAP
        assert finding.unmapped.get("wazuh.alert_id_truncated") == len(str(hostile))


def test_cap_id_exact_boundaries() -> None:
    """_cap_id is identity at the cap and exact-size with a hash above."""
    import hashlib

    unmapped: dict[str, Any] = {}
    exact = "V" * CAP
    assert wazuh._cap_id(exact, unmapped, "wazuh.probe_truncated") == exact
    assert "wazuh.probe_truncated" not in unmapped
    over = "V" * (CAP + 1)
    capped = wazuh._cap_id(over, unmapped, "wazuh.probe_truncated")
    assert len(capped) == CAP
    assert capped.startswith("V" * 100)
    assert "#" in capped
    expected = over[: CAP - 17] + "#" + hashlib.sha256(over.encode()).hexdigest()[:16]
    assert capped == expected
    assert unmapped["wazuh.probe_truncated"] == CAP + 1
    assert wazuh._cap_id(over, {}, "wazuh.probe_truncated") == capped


def test_typed_command_exact_size() -> None:
    """A sudo command keeps exactly CAP chars with the exact length."""
    finding, event, _key = wazuh.map_alert(_sudo_hit(command="C" * CAP))
    assert event is not None
    assert event.process is not None
    assert event.process.cmd_line == "C" * CAP
    assert "wazuh.command_truncated" not in event.unmapped
    finding, event, _key = wazuh.map_alert(_sudo_hit(command="C" * (CAP + 1)))
    assert event is not None
    assert event.process is not None
    assert event.process.cmd_line is not None
    assert len(event.process.cmd_line) == CAP
    assert event.unmapped.get("wazuh.command_truncated") == CAP + 1


def _serial(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True)


def test_cap_unmapped_string_exact_size() -> None:
    """A leftover string keeps exactly CAP chars with the exact length."""
    unmapped: dict[str, Any] = {}
    assert wazuh._cap_unmapped_value("S" * CAP, unmapped, "k") == "S" * CAP
    assert "k_truncated" not in unmapped
    assert wazuh._cap_unmapped_value("S" * (CAP + 1), unmapped, "k") == "S" * CAP
    assert unmapped["k_truncated"] == CAP + 1
    capped = wazuh._cap_unmapped_value("S" * (CAP + 1), {}, "k")
    assert isinstance(capped, str) and len(capped) == CAP


def test_cap_unmapped_list_serial_exact_and_over() -> None:
    """A list serializing to exactly the cap stays; one char over truncates."""
    exact = ["A" * (CAP - 4)]
    assert len(_serial(exact)) == CAP
    unmapped: dict[str, Any] = {}
    assert wazuh._cap_unmapped_value(exact, unmapped, "k") == exact
    assert "k_truncated" not in unmapped
    over = ["A" * (CAP - 3)]
    assert len(_serial(over)) == CAP + 1
    capped = wazuh._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == CAP + 1


def test_cap_unmapped_dict_serial_exact_and_over() -> None:
    """A dict serializing to exactly the cap stays; one char over truncates."""
    exact = {"a": "B" * (CAP - 9)}
    assert len(_serial(exact)) == CAP
    unmapped: dict[str, Any] = {}
    assert wazuh._cap_unmapped_value(exact, unmapped, "k") == exact
    assert "k_truncated" not in unmapped
    over = {"a": "B" * (CAP - 8)}
    assert len(_serial(over)) == CAP + 1
    capped = wazuh._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == CAP + 1


def test_cap_unmapped_tuple_over_serial_is_exact() -> None:
    """A tuple serializing over the cap becomes exactly CAP chars."""
    value = ("A" * (CAP + 100),)
    unmapped: dict[str, Any] = {}
    capped = wazuh._cap_unmapped_value(value, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == len(_serial(value))


def test_cap_unmapped_non_json_scalar_exact_and_over() -> None:
    """A non-JSON scalar (bytes) pins the fallback branch sizes exactly."""
    exact = b"A" * (CAP - 5)
    assert len(_serial(exact)) == CAP
    unmapped: dict[str, Any] = {}
    assert wazuh._cap_unmapped_value(exact, unmapped, "k") == exact
    assert "k_truncated" not in unmapped
    over = b"A" * (CAP - 4)
    assert len(_serial(over)) == CAP + 1
    capped = wazuh._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == CAP + 1


def test_cap_unmapped_list_count_exact_boundaries() -> None:
    """LIST_CAP items stay identical; one more truncates to LIST_CAP."""
    unmapped: dict[str, Any] = {}
    exact = [0] * LIST_CAP
    kept = wazuh._cap_unmapped_value(exact, unmapped, "k")
    assert kept is exact
    assert "k_truncated" not in unmapped
    over = [0] * (LIST_CAP + 1)
    capped = wazuh._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, list) and len(capped) == LIST_CAP
    assert unmapped["k_truncated"] == len(_serial(over))


def test_cap_unmapped_dict_count_exact_boundaries() -> None:
    """LIST_CAP keys stay identical; one more truncates to LIST_CAP."""
    unmapped: dict[str, Any] = {}
    exact = {f"k{index}": index for index in range(LIST_CAP)}
    kept = wazuh._cap_unmapped_value(exact, unmapped, "k")
    assert kept == exact
    assert "k_truncated" not in unmapped
    over = {f"k{index}": index for index in range(LIST_CAP + 1)}
    capped = wazuh._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, dict) and len(capped) == LIST_CAP
    assert unmapped["k_truncated"] == len(_serial(over))


def test_cap_unmapped_tuple_count_exact_boundary() -> None:
    """LIST_CAP + 1 tuple items truncate to a LIST_CAP tuple with length."""
    unmapped: dict[str, Any] = {}
    exact = (0,) * LIST_CAP
    assert wazuh._cap_unmapped_value(exact, unmapped, "k") is exact
    assert "k_truncated" not in unmapped
    over = (0,) * (LIST_CAP + 1)
    capped = wazuh._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, tuple) and len(capped) == LIST_CAP
    assert unmapped["k_truncated"] == len(_serial(list(over)))


def _mitre_hit(techniques: Any, tactics: Any, ids: Any) -> dict[str, Any]:
    hit = _sudo_hit()
    hit["_source"]["rule"]["mitre"] = {
        "id": ids,
        "tactic": tactics,
        "technique": techniques,
    }
    return hit


def test_mitre_technique_name_exact_size() -> None:
    """A technique name keeps exactly CAP chars with the exact length."""
    finding, _, _ = wazuh.map_alert(_mitre_hit(["N" * CAP], ["Esc"], ["T1059"]))
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and attacks[0].technique is not None
    assert attacks[0].technique.name == "N" * CAP
    assert "wazuh.mitre_technique_truncated" not in finding.unmapped
    finding, _, _ = wazuh.map_alert(_mitre_hit(["N" * (CAP + 1)], ["Esc"], ["T1059"]))
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and attacks[0].technique is not None
    assert attacks[0].technique.name is not None
    assert len(attacks[0].technique.name) == CAP
    assert finding.unmapped.get("wazuh.mitre_technique_truncated") == CAP + 1


def test_mitre_tactic_name_exact_size() -> None:
    """A tactic name keeps exactly CAP chars with the exact length."""
    finding, _, _ = wazuh.map_alert(_mitre_hit(["Sudo"], ["A" * CAP], ["TA0004"]))
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and attacks[0].tactic is not None
    assert attacks[0].tactic.name == "A" * CAP
    assert "wazuh.mitre_tactic_truncated" not in finding.unmapped
    finding, _, _ = wazuh.map_alert(_mitre_hit(["Sudo"], ["A" * (CAP + 1)], ["TA0004"]))
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and attacks[0].tactic is not None
    assert attacks[0].tactic.name is not None
    assert len(attacks[0].tactic.name) == CAP
    assert finding.unmapped.get("wazuh.mitre_tactic_truncated") == CAP + 1


def test_mitre_id_exact_size() -> None:
    """A passing technique id at the cap stays; one over caps exactly."""
    exact = "T" + "1" * (CAP - 1)
    assert len(exact) == CAP
    finding, _, _ = wazuh.map_alert(_mitre_hit(["Sudo"], ["Esc"], [exact]))
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and attacks[0].technique is not None
    assert attacks[0].technique.uid == exact
    assert "wazuh.mitre_id_truncated" not in finding.unmapped
    over = "T" + "1" * CAP
    finding, _, _ = wazuh.map_alert(_mitre_hit(["Sudo"], ["Esc"], [over]))
    assert finding.finding_info is not None
    attacks = finding.finding_info.attacks
    assert attacks is not None and attacks[0].technique is not None
    assert attacks[0].technique.uid is not None
    assert len(attacks[0].technique.uid) == CAP
    assert attacks[0].technique.uid == over[:CAP]
    assert finding.unmapped.get("wazuh.mitre_id_truncated") == CAP + 1


def test_caps_match_across_normalizers() -> None:
    """Both normalizers bound text and leftover counts at the same lengths."""
    assert WAZUH_RAW_DATA_CAP == WINDOWS_TEXT_CAP == CAP
    assert WAZUH_UNMAPPED_LIST_CAP == WINDOWS_UNMAPPED_LIST_CAP == LIST_CAP
    assert ENTITY_KEY_CAP == CAP


def test_windows_cap_text_exact_size() -> None:
    """A Windows typed slot keeps exactly CAP chars with the exact length."""
    fields: dict[str, Any] = {}
    assert win._cap_text("W" * CAP, fields, "windows.probe_truncated") == "W" * CAP
    assert "windows.probe_truncated" not in fields
    capped = win._cap_text("W" * (CAP + 1), fields, "windows.probe_truncated")
    assert capped is not None and len(capped) == CAP
    assert fields["windows.probe_truncated"] == CAP + 1


def test_windows_cap_unmapped_string_exact_size() -> None:
    """A Windows leftover string keeps exactly CAP chars with the length."""
    unmapped: dict[str, Any] = {}
    assert win._cap_unmapped_value("W" * CAP, unmapped, "k") == "W" * CAP
    assert "k_truncated" not in unmapped
    capped = win._cap_unmapped_value("W" * (CAP + 1), unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == CAP + 1


def test_windows_cap_unmapped_list_serial_exact_and_over() -> None:
    """A Windows list serializing to the cap stays; one over truncates."""
    exact = ["A" * (CAP - 4)]
    assert len(_serial(exact)) == CAP
    unmapped: dict[str, Any] = {}
    assert win._cap_unmapped_value(exact, unmapped, "k") == exact
    assert "k_truncated" not in unmapped
    over = ["A" * (CAP - 3)]
    capped = win._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == CAP + 1


def test_windows_cap_unmapped_dict_serial_exact_and_over() -> None:
    """A Windows dict serializing to the cap stays; one over truncates."""
    exact = {"a": "B" * (CAP - 9)}
    assert len(_serial(exact)) == CAP
    unmapped: dict[str, Any] = {}
    assert win._cap_unmapped_value(exact, unmapped, "k") == exact
    assert "k_truncated" not in unmapped
    over = {"a": "B" * (CAP - 8)}
    capped = win._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == CAP + 1


def test_windows_cap_unmapped_tuple_and_scalar_exact() -> None:
    """Windows tuple and non-JSON scalar branches pin exact sizes."""
    unmapped: dict[str, Any] = {}
    exact_tuple = (0,) * LIST_CAP
    assert win._cap_unmapped_value(exact_tuple, unmapped, "k") is exact_tuple
    assert "k_truncated" not in unmapped
    over_tuple = (0,) * (LIST_CAP + 1)
    capped_tuple = win._cap_unmapped_value(over_tuple, unmapped, "k")
    assert isinstance(capped_tuple, tuple) and len(capped_tuple) == LIST_CAP
    assert unmapped["k_truncated"] == len(_serial(list(over_tuple)))
    exact_bytes = b"A" * (CAP - 5)
    assert len(_serial(exact_bytes)) == CAP
    assert win._cap_unmapped_value(exact_bytes, unmapped, "j") == exact_bytes
    assert "j_truncated" not in unmapped
    over_bytes = b"A" * (CAP - 4)
    capped_scalar = win._cap_unmapped_value(over_bytes, unmapped, "j")
    assert isinstance(capped_scalar, str) and len(capped_scalar) == CAP
    assert unmapped["j_truncated"] == CAP + 1


def test_windows_cap_unmapped_list_count_exact_boundaries() -> None:
    """LIST_CAP Windows items stay identical; one more truncates."""
    unmapped: dict[str, Any] = {}
    exact = [0] * LIST_CAP
    assert win._cap_unmapped_value(exact, unmapped, "k") is exact
    assert "k_truncated" not in unmapped
    over = [0] * (LIST_CAP + 1)
    capped = win._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, list) and len(capped) == LIST_CAP
    assert unmapped["k_truncated"] == len(_serial(over))


def test_windows_cap_unmapped_dict_count_exact_boundaries() -> None:
    """LIST_CAP Windows keys stay identical; one more truncates."""
    unmapped: dict[str, Any] = {}
    exact = {f"k{index}": index for index in range(LIST_CAP)}
    kept = win._cap_unmapped_value(exact, unmapped, "k")
    assert kept == exact
    assert "k_truncated" not in unmapped
    over = {f"k{index}": index for index in range(LIST_CAP + 1)}
    capped = win._cap_unmapped_value(over, unmapped, "k")
    assert isinstance(capped, dict) and len(capped) == LIST_CAP
    assert unmapped["k_truncated"] == len(_serial(over))


def test_windows_cap_unmapped_tuple_over_serial_is_exact() -> None:
    """A Windows tuple serializing over the cap becomes exactly CAP chars."""
    value = ("A" * (CAP + 100),)
    unmapped: dict[str, Any] = {}
    capped = win._cap_unmapped_value(value, unmapped, "k")
    assert isinstance(capped, str) and len(capped) == CAP
    assert unmapped["k_truncated"] == len(_serial(value))


def test_entity_key_combination_exact_size() -> None:
    """A domain\\user key combining past the cap keeps exactly CAP chars."""
    assert compute_entity_keys(user="U", domain="D").user == "d\\u"
    exact = compute_entity_keys(user="U" * (CAP - 8), domain="EXAMPLE")
    assert exact.user is not None
    assert len(exact.user) == CAP
    over = compute_entity_keys(user="U" * (CAP - 7), domain="EXAMPLE")
    assert over.user is not None
    assert len(over.user) == CAP
    assert over.user == "example\\" + "u" * (CAP - 8)


def test_entity_key_combination_end_to_end() -> None:
    """A hostile logon user keeps the derived entity key within the cap."""
    record = fx.flat_security_logon(success=True)
    record["TargetUserName"] = "T" * 300_000
    channel, event_id, record_id, fields, computer, raw_time = extract_json_parts(
        record, 1
    )
    event = normalize_event(
        channel=channel,
        event_id=event_id,
        fields=sanitize_record(fields),
        computer=computer,
        uid=make_uid("probe", record_id),
        raw_time=raw_time,
        raw_record=sanitize_record(record),
    )
    assert event.entity_keys is not None
    assert event.entity_keys.user is not None
    assert len(event.entity_keys.user) == CAP


def test_raw_leaf_exact_size_both_normalizers() -> None:
    """A raw_data leaf keeps exactly CAP chars with the exact JSON path."""
    truncated: dict[str, int] = {}
    assert wazuh._cap_raw_leaves("R" * CAP, truncated) == "R" * CAP
    assert truncated == {}
    assert wazuh._cap_raw_leaves("R" * (CAP + 1), truncated) == "R" * CAP
    assert truncated == {"$": CAP + 1}
    win_truncated: dict[str, int] = {}
    assert win._cap_raw_leaves("R" * CAP, win_truncated) == "R" * CAP
    assert win_truncated == {}
    assert win._cap_raw_leaves("R" * (CAP + 1), win_truncated) == "R" * CAP
    assert win_truncated == {"$": CAP + 1}


def test_cap_unmapped_nested_leaf_exact_size_both_normalizers() -> None:
    """A nested leaf keeps exactly CAP chars; one over truncates to CAP."""
    for cap_nested in (wazuh._cap_unmapped_nested, win._cap_unmapped_nested):
        assert cap_nested("S" * CAP) == "S" * CAP
        over = cap_nested("S" * (CAP + 1))
        assert isinstance(over, str) and over == "S" * CAP
        nested = cap_nested({"k": ["S" * (CAP + 1)]})
        assert isinstance(nested, dict)
        leaf = nested["k"][0]
        assert isinstance(leaf, str) and leaf == "S" * CAP
        tupled = cap_nested(({"k": "S" * (CAP + 1)},))
        assert isinstance(tupled, tuple)
        tuple_leaf = tupled[0]["k"]
        assert isinstance(tuple_leaf, str) and tuple_leaf == "S" * CAP
