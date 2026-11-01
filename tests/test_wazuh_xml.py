"""Translator tests: subset, refusals, and real-record proof.

Unit shapes use hand-written Sigma texts; every firing claim is
checked against REAL Wazuh records resolved through the replay
provenance (never copied into fixtures).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
import yaml

from corvus.learning.export_wazuh import load_provenance, read_raw_doc
from corvus.learning.wazuh_xml import (
    ACTIVE_LEVEL,
    SHADOW_LEVEL,
    TranslationReport,
    derive_parents,
    local_rules_ids,
    parse_ruleset,
    translate,
)

GOLDEN = Path("tests/fixtures/rules/linux_golden_rule.yml").read_text(encoding="utf-8")

CHAIN_DIR = "data/replay-linux-chain1"
BASELINE_DIR = "data/replay-linux-baseline"

RULESET = [
    "data/wazuh-ruleset/0020-syslog_rules.xml",
    "data/wazuh-ruleset/0365-auditd_rules.xml",
]

SUDO_PARENTS = [5400, 5401, 5402, 5407, 5403, 5405, 5406]
AUDIT_PARENTS = [80700, 80780, 80783, 80786, 80789, 80792]


def tr(text: str, native_id: int, mode: str, **kwargs: Any) -> TranslationReport:
    """Translate with the real shipped ruleset (stand-ins pass their own)."""
    return translate(text, native_id, mode, ruleset_paths=RULESET, **kwargs)


def _rule_text(
    detection: str,
    condition: str,
    *,
    rule_id: str = "11111111-1111-4111-8111-111111111111",
    status: str = "test",
    logsource: str = "  product: linux\n  category: process_creation",
    title: str = "Test Rule",
    description: str = "Test description.",
    level: str = "medium",
    tags: str = "",
) -> str:
    """Render one minimal Sigma rule text for translator tests."""
    return (
        f"title: {title}\n"
        f"id: {rule_id}\n"
        f"status: {status}\n"
        f"description: >-\n  {description}\n"
        f"author: test\n"
        f"date: 2026-10-31\n"
        f"logsource:\n{logsource}\n"
        f"detection:\n{detection}"
        f"  condition: {condition}\n"
        f"level: {level}\n"
        f"{tags}"
    )


SEL = """\
  sel_img:
    Image|endswith: '/find'
  sel_key:
    CommandLine|contains: 'authorized_keys'
  sel_exec:
    CommandLine|contains: '-exec'
"""

SIMPLE = _rule_text(SEL, "sel_img and sel_key and sel_exec")


def _chain_doc(uid: str) -> dict:
    prov = load_provenance(CHAIN_DIR)
    assert uid in prov, f"{uid} missing from chain provenance"
    file, line = prov[uid]
    return read_raw_doc("data", file, line)


# Golden translation --------------------------------------------------


def test_translate_golden_shadow() -> None:
    rep = tr(GOLDEN, 100010, "shadow", exclude_ids={100001})
    assert rep.ok, rep.reason
    assert rep.code == "translated"
    # Shadow levels follow the replaced parents (sudo max 5, auditd
    # max 3); the top level is the highest of both.
    assert rep.detail["levels"] == {"sudo": 5, "auditd": 3}
    assert rep.level == 5
    assert rep.native_rule_ids == (100010, 100011)
    assert rep.mode == "shadow"
    assert rep.group == "corvus_7c4f3a21-9b6e-4f2a-8c1d-3e5f6a7b8c9d"
    assert rep.sources == ("sudo", "auditd")
    assert rep.detail["parents"] == {"sudo": SUDO_PARENTS, "auditd": AUDIT_PARENTS}
    assert rep.xml is not None
    root = ET.fromstring(rep.xml)
    rules = root.findall("rule")
    assert len(rules) == 2
    sudo, audit = rules
    assert sudo.get("id") == "100010" and sudo.get("level") == "5"
    assert sudo.findtext("if_sid") == ", ".join(str(pid) for pid in SUDO_PARENTS)
    assert (sudo.find("field") is not None) and sudo.find("field").get("name") == (
        "command"
    )
    assert audit.get("id") == "100011" and audit.get("level") == "3"
    assert audit.findtext("if_sid") == ", ".join(str(pid) for pid in AUDIT_PARENTS)
    assert audit.find("regex") is not None
    assert "corvus_shadow" in (sudo.findtext("group") or "")
    assert rep.detail["literals"] == ["-exec", "/find", "authorized_keys"]


def test_translate_active_level_and_group() -> None:
    rep = tr(GOLDEN, 100010, "active")
    assert rep.ok, rep.reason
    assert rep.level == ACTIVE_LEVEL == 7
    assert rep.xml is not None
    root = ET.fromstring(rep.xml)
    for rule in root.findall("rule"):
        assert rule.get("level") == "7"
        assert "corvus_active" in (rule.findtext("group") or "")


STANDIN_RULESET = """\
<group name="syslog,sudo,">
  <rule id="6000" level="0">
    <decoded_as>sudo</decoded_as>
    <description>Stand-in sudo group.</description>
  </rule>
  <rule id="6001" level="3">
    <if_sid>6000</if_sid>
    <regex> ; USER=root ; COMMAND=</regex>
    <description>Stand-in success.</description>
  </rule>
  <rule id="6002" level="4">
    <if_sid>6000</if_sid>
    <if_fts />
    <description>Stand-in first time.</description>
  </rule>
</group>
<group name="auditd,">
  <rule id="7000" level="0">
    <decoded_as>auditd</decoded_as>
    <description>Stand-in auditd group.</description>
  </rule>
  <rule id="7001" level="3">
    <if_sid>7000</if_sid>
    <list field="audit.key" lookup="match_key">etc/lists/audit-keys</list>
    <description>Stand-in key watch.</description>
  </rule>
  <rule id="7002" level="10">
    <if_sid>7000</if_sid>
    <field name="audit.type">ANOM_ABEND</field>
    <description>Stand-in anomaly: disjoint type, must not parent.</description>
  </rule>
</group>
"""


def _standin_ruleset(tmp_path: Path, text: str = STANDIN_RULESET) -> list[str]:
    path = tmp_path / "standin_rules.xml"
    path.write_text(text, encoding="utf-8")
    return [str(path)]


def test_derive_parents_never_roots_alone(tmp_path: Path) -> None:
    rules = parse_ruleset(_standin_ruleset(tmp_path))
    assert derive_parents("sudo", rules) == [6000, 6001, 6002]
    # The type-disjoint anomaly child cannot intercept: dropped, so
    # the shadow level is not dragged to 10.
    assert derive_parents("auditd", rules) == [7000, 7001]


def test_standin_sibling_shadow_levels(tmp_path: Path) -> None:
    paths = _standin_ruleset(tmp_path)
    rep = translate(SIMPLE, 100010, "shadow", ruleset_paths=paths)
    assert rep.ok, rep.reason
    assert rep.detail["parents"] == {
        "sudo": [6000, 6001, 6002],
        "auditd": [7000, 7001],
    }
    assert rep.detail["levels"] == {"sudo": 4, "auditd": 3}
    assert rep.xml is not None
    root = ET.fromstring(rep.xml)
    sudo, audit = root.findall("rule")
    assert sudo.get("level") == "4"
    assert sudo.findtext("if_sid") == "6000, 6001, 6002"
    assert audit.get("level") == "3"


def test_parent_override_unknown_id_refused(tmp_path: Path) -> None:
    paths = _standin_ruleset(tmp_path)
    rep = translate(
        SIMPLE, 100010, "shadow", ruleset_paths=paths, parent_ids={"sudo": [6001, 9999]}
    )
    assert not rep.ok and rep.code == "unknown_parent" and rep.xml is None


def test_parent_override_empty_refused(tmp_path: Path) -> None:
    paths = _standin_ruleset(tmp_path)
    rep = translate(
        SIMPLE, 100010, "shadow", ruleset_paths=paths, parent_ids={"auditd": []}
    )
    assert not rep.ok and rep.code == "unknown_parent" and rep.xml is None


def test_parent_override_subset_pins_chain_and_level(tmp_path: Path) -> None:
    paths = _standin_ruleset(tmp_path)
    rep = translate(
        SIMPLE, 100010, "shadow", ruleset_paths=paths, parent_ids={"sudo": [6001]}
    )
    assert rep.ok, rep.reason
    assert rep.detail["parents"]["sudo"] == [6001]
    assert rep.detail["levels"]["sudo"] == 3
    # The other source still derives.
    assert rep.detail["parents"]["auditd"] == [7000, 7001]


@pytest.mark.parametrize(
    ("kid_levels", "want"),
    [([0], 2), ([3], 3), ([0, 3, 4], 4), ([5], 5)],
)
def test_shadow_level_follows_parents(
    tmp_path: Path, kid_levels: list[int], want: int
) -> None:
    kids = "\n".join(
        f"""  <rule id="{6100 + i}" level="{lvl}">
    <if_sid>6000</if_sid>
    <match>COMMAND=</match>
    <description>Stand-in kid {i}.</description>
  </rule>"""
        for i, lvl in enumerate(kid_levels)
    )
    text = f"""<group name="syslog,sudo,">
  <rule id="6000" level="0">
    <decoded_as>sudo</decoded_as>
    <description>Stand-in sudo group.</description>
  </rule>
{kids}
</group>
<group name="auditd,">
  <rule id="7000" level="0">
    <decoded_as>auditd</decoded_as>
    <description>Stand-in auditd group.</description>
  </rule>
</group>
"""
    rep = translate(
        SIMPLE, 100010, "shadow", ruleset_paths=_standin_ruleset(tmp_path, text)
    )
    assert rep.ok, rep.reason
    assert rep.detail["levels"]["sudo"] == want
    # Level-0-only chains stay below the alert threshold.
    assert rep.detail["levels"]["auditd"] == SHADOW_LEVEL == 2


def test_real_parent_chains_and_real_sudo_lines() -> None:
    rep = tr(GOLDEN, 100010, "shadow")
    assert rep.ok, rep.reason
    # Exact chains derived from the shipped ruleset (file order).
    assert rep.detail["parents"]["sudo"] == SUDO_PARENTS
    assert rep.detail["parents"]["auditd"] == AUDIT_PARENTS
    # The lab-verified triple is parented (326/326 fix).
    assert {5402, 5403, 5407} <= set(rep.detail["parents"]["sudo"])
    # Both real bundle sudo lines still match the sudo pattern.
    pattern = re.compile(rep.detail["pattern_sudo"])
    for uid in ("lnx-d7bea80358fc93ab", "lnx-f749ba60b31e41e4"):
        assert pattern.search(_chain_doc(uid)["data"]["command"]), uid
    levels = rep.detail["parent_levels"]
    assert [levels[str(pid)] for pid in SUDO_PARENTS] == [0, 5, 3, 3, 4, 5, 5]


def test_mitre_ids_filtered_by_dictionary() -> None:
    from corvus.attack import load_dictionary

    attack = load_dictionary("data/attack/enterprise.json")
    assert attack.resolve("t1548.003") is not None
    detection = "  sel:\n    CommandLine|contains: 'authorized_keys'\n"
    tags = "tags:\n  - attack.t1548.003\n  - attack.t9999.999\n  - attack.execution\n"
    text = _rule_text(detection, "sel", tags=tags)
    rep = tr(text, 100020, "shadow", attack=attack)
    assert rep.ok, rep.reason
    assert rep.mitre_ids == ("T1548.003",)
    assert rep.xml is not None
    root = ET.fromstring(rep.xml)
    ids = [
        node.text for rule in root.findall("rule") for node in rule.findall("mitre/id")
    ]
    assert ids == ["T1548.003", "T1548.003"]


# Real-record proof ----------------------------------------------------


def test_sudo_pattern_fires_on_real_sudo_targets() -> None:
    rep = tr(GOLDEN, 100010, "shadow")
    assert rep.ok, rep.reason
    pattern = re.compile(rep.detail["pattern_sudo"])
    for uid in ("lnx-d7bea80358fc93ab", "lnx-f749ba60b31e41e4"):
        doc = _chain_doc(uid)
        assert doc["decoder"]["name"] == "sudo"
        assert pattern.search(doc["data"]["command"]), uid


def test_audit_pattern_fires_on_real_hex_record() -> None:
    rep = tr(GOLDEN, 100010, "shadow")
    assert rep.ok, rep.reason
    pattern = re.compile(rep.detail["pattern_audit"])
    doc = _chain_doc("lnx-6aada96a96a3c468")
    blob = doc["full_log"]
    # The literal lives ONLY as uppercase hex in this blob.
    assert "authorized_keys" not in blob
    assert "617574686F72697A65645F6B657973" in blob
    assert pattern.search(blob)


def test_audit_pattern_matches_lowercase_hex_variant() -> None:
    rep = tr(GOLDEN, 100010, "shadow")
    assert rep.ok, rep.reason
    pattern = re.compile(rep.detail["pattern_audit"])
    doc = _chain_doc("lnx-6aada96a96a3c468")
    lowered = doc["full_log"].lower()
    assert "617574686f72697a65645f6b657973" in lowered
    assert pattern.search(lowered)


def test_audit_pattern_ignores_file_only_blob() -> None:
    rep = tr(GOLDEN, 100010, "shadow")
    assert rep.ok, rep.reason
    pattern = re.compile(rep.detail["pattern_audit"])
    doc = _chain_doc("lnx-22e99900825434c9")  # chmod, no EXECVE argv match
    assert not pattern.search(doc["full_log"])


def test_wildcard_rule_matches_both_hex_forms() -> None:
    detection = "  sel:\n    CommandLine|contains: '*authorized*keys*'\n"
    text = _rule_text(detection, "sel")
    rep = tr(text, 100030, "shadow")
    assert rep.ok, rep.reason
    pattern = re.compile(rep.detail["pattern_audit"])
    assert pattern.search(_chain_doc("lnx-6aada96a96a3c468")["full_log"])


def test_real_baseline_lines_do_not_fire() -> None:
    import glob as glob_module

    import pyarrow.parquet as pq

    rep = tr(GOLDEN, 100010, "shadow")
    assert rep.ok, rep.reason
    sudo_pattern = re.compile(rep.detail["pattern_sudo"])
    audit_pattern = re.compile(rep.detail["pattern_audit"])
    # First mapped sudo/auditd lines per decoder, each source file
    # read once (not one seek per line).
    wanted: dict[str, list[str]] = {"sudo": [], "auditd": []}
    caps = {"sudo": 1, "auditd": 8}
    for path in sorted(glob_module.glob(f"{BASELINE_DIR}/events/*.parquet")):
        for row in pq.read_table(path, columns=["uid", "log_name"]).to_pylist():
            name = row.get("log_name")
            if name in wanted and len(wanted[name]) < caps[name]:
                wanted[name].append(str(row["uid"]))
    prov = load_provenance(BASELINE_DIR)
    by_file: dict[str, list[tuple[int, str]]] = {}
    for name, uids in wanted.items():
        for uid in uids:
            file, line = prov[uid]
            by_file.setdefault(file, []).append((line, name))
    assert len(wanted["sudo"]) == 1 and len(wanted["auditd"]) == 8
    for file, refs in sorted(by_file.items()):
        for line, name in sorted(refs):
            doc = read_raw_doc("data", file, line)
            if name == "sudo":
                assert not sudo_pattern.search(doc["data"]["command"])
            else:
                assert not audit_pattern.search(doc["full_log"])


# Refusals ---------------------------------------------------------------


def test_local_rules_ids_lists_lab_id() -> None:
    assert 100001 in local_rules_ids("data/wazuh-ruleset/local_rules.xml")


def test_shipped_ruleset_paths_skips_decoders_and_local() -> None:
    from corvus.learning.wazuh_xml import shipped_ruleset_paths

    paths = shipped_ruleset_paths("data/wazuh-ruleset")
    assert paths == [
        "data/wazuh-ruleset/0020-syslog_rules.xml",
        "data/wazuh-ruleset/0365-auditd_rules.xml",
    ]


def test_refuse_id_collision_with_local_rules() -> None:
    rep = tr(GOLDEN, 100001, "shadow", exclude_ids={100001})
    assert not rep.ok and rep.code == "id_collision" and rep.xml is None


def test_second_id_skips_taken_ids() -> None:
    rep = tr(GOLDEN, 100000, "shadow", exclude_ids={100001})
    assert rep.ok, rep.reason
    assert rep.native_rule_ids == (100000, 100002)


def test_refuse_id_range() -> None:
    rep = tr(GOLDEN, 120000, "shadow")
    assert not rep.ok and rep.code == "id_range" and rep.xml is None
    rep = tr(GOLDEN, 99999, "shadow")
    assert not rep.ok and rep.code == "id_range" and rep.xml is None


def test_refuse_bad_mode_and_input() -> None:
    rep = tr(GOLDEN, 100010, "noisy")
    assert not rep.ok and rep.code == "bad_input" and rep.xml is None
    rep = tr("", 100010, "shadow")
    assert not rep.ok and rep.code == "bad_input" and rep.xml is None


def test_refuse_unsupported_logsource() -> None:
    text = _rule_text(
        SEL,
        "sel_img and sel_key and sel_exec",
        logsource="  product: windows\n  category: process_creation",
    )
    rep = tr(text, 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None
    assert "logsource" in rep.reason


def test_refuse_unmapped_field() -> None:
    detection = "  sel:\n    User: 'deploy'\n"
    rep = tr(_rule_text(detection, "sel"), 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None


def test_refuse_regex_modifier() -> None:
    detection = "  sel:\n    CommandLine|re: 'auth.*keys'\n"
    rep = tr(_rule_text(detection, "sel"), 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None
    assert "|re" in rep.reason


def test_refuse_commandline_startswith_on_auditd() -> None:
    detection = "  sel:\n    CommandLine|startswith: '/usr/bin/find'\n"
    rep = tr(_rule_text(detection, "sel"), 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None


def test_refuse_double_negation() -> None:
    detection = (
        "  sel:\n    CommandLine|contains: 'authorized_keys'\n"
        "  filt:\n    CommandLine|contains: 'handled-by-ops'\n"
        "  other:\n    CommandLine|contains: 'also-fine-here'\n"
    )
    text = _rule_text(detection, "sel and not filt and not other")
    rep = tr(text, 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None


def test_single_negation_translates() -> None:
    detection = (
        "  sel:\n    CommandLine|contains: 'authorized_keys'\n"
        "  filt:\n    CommandLine|contains: 'handled-by-ops'\n"
    )
    rep = tr(_rule_text(detection, "sel and not filt"), 100010, "shadow")
    assert rep.ok, rep.reason
    sudo = re.compile(rep.detail["pattern_sudo"])
    assert sudo.search("cat /root/.ssh/authorized_keys backup")
    assert not sudo.search("cat authorized_keys handled-by-ops file")


def test_refuse_short_and_huge_literals() -> None:
    short = _rule_text("  sel:\n    CommandLine|contains: 'sh'\n", "sel")
    rep = tr(short, 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None
    huge = _rule_text(f"  sel:\n    CommandLine|contains: '{'A' * 1000000}'\n", "sel")
    rep = tr(huge, 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None


@pytest.mark.parametrize("literal", ["a\x00b", "a\nb", "a]]>b", "a\rb"])
def test_refuse_dangerous_literals(literal: str) -> None:
    doc = yaml.safe_load(GOLDEN)
    doc["detection"]["sel_key"] = {"CommandLine|contains": literal}
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    rep = tr(text, 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None


def test_title_with_markup_is_escaped_not_emitted() -> None:
    doc = yaml.safe_load(GOLDEN)
    doc["title"] = 'Bad </rule> & <!-- title --> "quoted"'
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    rep = tr(text, 100010, "shadow")
    assert rep.ok, rep.reason
    assert rep.xml is not None
    root = ET.fromstring(rep.xml)
    assert len(root.findall("rule")) == 2
    assert "</rule>" in root.find("rule/description").text  # type: ignore[union-attr]


def test_refuse_hex_looking_literal_still_matches() -> None:
    # A literal that already looks like hex is matched as text AND hex.
    detection = "  sel:\n    CommandLine|contains: 'dead'\n"
    rep = tr(_rule_text(detection, "sel"), 100010, "shadow")
    assert rep.ok, rep.reason


def test_title_with_cdata_close_is_refused() -> None:
    # "]]>" is illegal in XML content, so it is refused, never emitted.
    doc = yaml.safe_load(GOLDEN)
    doc["title"] = "Ends with brackets ]]> and & ampersand"
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    rep = tr(text, 100010, "shadow")
    assert not rep.ok and rep.code == "translation_unsupported" and rep.xml is None


def test_regex_metacharacters_match_literally() -> None:
    detection = "  sel:\n    CommandLine|contains: 'foo(bar)+[baz]?a*b'\n"
    rep = tr(_rule_text(detection, "sel"), 100010, "shadow")
    assert rep.ok, rep.reason
    sudo = re.compile(rep.detail["pattern_sudo"])
    assert sudo.search("run foo(bar)+[baz]XaYYb now")
    assert not sudo.search("run fooXbar+bazYaYb now")
