"""Tests for ATT&CK technique-id finders and masks."""

import json

from corvus.normalize.technique_ids import (
    find_technique_ids,
    has_in_band_technique_id,
    mask_payload,
    mask_technique_ids,
)


def _tagged_record() -> dict[str, object]:
    """A record whose RuleName and Message carry the tag (no real content)."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "EventIdx": 700,
        "Hostname": "web01.example.com",
        "RuleName": (
            "technique_id=T1003,technique_name=Credential Dumping, source=modular"
        ),
        "Message": (
            "hit technique_name=Masquerading\\r\\nUtcTime: 2024-05-02 14:03:00"
        ),
        "Quoted": 'a technique_name=Masquerading", more',
    }


def test_masked_serialized_json_still_parses() -> None:
    masked = mask_technique_ids(json.dumps(_tagged_record()))
    parsed = json.loads(masked)
    assert (
        parsed["RuleName"] == "technique_id=[TECHNIQUE-ID],"
        "technique_name=[TECHNIQUE-NAME], source=modular"
    )
    assert parsed["Message"] == (
        "hit technique_name=[TECHNIQUE-NAME]\\r\\nUtcTime: 2024-05-02 14:03:00"
    )
    assert "UtcTime: 2024-05-02 14:03:00" in parsed["Message"]
    assert parsed["Quoted"] == 'a technique_name=[TECHNIQUE-NAME]", more'


def test_mask_payload_masks_values_and_nothing_else() -> None:
    record = _tagged_record()
    masked = mask_payload(record)
    assert masked == {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "EventIdx": 700,
        "Hostname": "web01.example.com",
        "RuleName": (
            "technique_id=[TECHNIQUE-ID],"
            "technique_name=[TECHNIQUE-NAME], source=modular"
        ),
        "Message": (
            "hit technique_name=[TECHNIQUE-NAME]\\r\\nUtcTime: 2024-05-02 14:03:00"
        ),
        "Quoted": 'a technique_name=[TECHNIQUE-NAME]", more',
    }


def test_mask_payload_walks_containers_keys_untouched() -> None:
    payload = {
        "technique_name": "T1003",  # key stays, value masks
        "nested": ["a T1003 b", ("c technique_name=X, d",)],
        "count": 3,
        "nothing": None,
    }
    assert mask_payload(payload) == {
        "technique_name": "[TECHNIQUE-ID]",
        "nested": ["a [TECHNIQUE-ID] b", ("c technique_name=[TECHNIQUE-NAME], d",)],
        "count": 3,
        "nothing": None,
    }
    assert mask_payload("plain T1003") == "plain [TECHNIQUE-ID]"
    assert mask_payload(42) == 42
    assert mask_payload(None) is None


def test_rulename_masks_id_and_name() -> None:
    assert (
        mask_technique_ids("technique_id=T1003,technique_name=Credential Dumping")
        == "technique_id=[TECHNIQUE-ID],technique_name=[TECHNIQUE-NAME]"
    )
    # Delimiters survive byte-identical: semicolon, quote, newline, end.
    assert (
        mask_technique_ids('a technique_name=Masquerading";b')
        == 'a technique_name=[TECHNIQUE-NAME]";b'
    )
    assert (
        mask_technique_ids("technique_name=Install Root Certificate;next=1")
        == "technique_name=[TECHNIQUE-NAME];next=1"
    )
    assert (
        mask_technique_ids("TECHNIQUE_NAME=Defense Evasion\nmore")
        == "TECHNIQUE_NAME=[TECHNIQUE-NAME]\nmore"
    )
    assert mask_technique_ids("technique_name=") == "technique_name=[TECHNIQUE-NAME]"


def test_text_without_tags_is_unchanged() -> None:
    for plain in (
        "powershell.exe -NoProfile -Command Get-Process",
        "technique wrote this line",  # no tag, no id
        "XT1234 and T12345 stay",
    ):
        assert mask_technique_ids(plain) == plain


def test_flag_fires_on_name_tag_without_id() -> None:
    class _Tagged:
        def model_dump(self) -> dict[str, object]:
            return {"unmapped": {"RuleName": "technique_name=Credential Dumping"}}

    class _Clean:
        def model_dump(self) -> dict[str, object]:
            return {"unmapped": {"RuleName": "technique, no tag here"}}

    assert has_in_band_technique_id(_Tagged()) is True
    assert has_in_band_technique_id(_Clean()) is False


def test_find_technique_ids_in_attack_paths() -> None:
    assert find_technique_ids(r"C:\AtomicRedTeam\atomics\T1218.005\payload.ps1") == [
        "T1218.005"
    ]
    assert find_technique_ids("used T1003 and t1059.001 today") == [
        "T1003",
        "T1059.001",
    ]
    assert find_technique_ids("(T1548.003)") == ["T1548.003"]
    assert find_technique_ids("no ids here") == []


def test_mask_keeps_everything_else_byte_identical() -> None:
    text = r"C:\AtomicRedTeam\atomics\T1218.005\x.ps1 ran T1003 ok"
    masked = mask_technique_ids(text)
    assert masked == (
        r"C:\AtomicRedTeam\atomics\[TECHNIQUE-ID]\x.ps1 "
        "ran [TECHNIQUE-ID] ok"
    )
    assert masked.replace("[TECHNIQUE-ID]", "XXXXX") == text.replace(
        "T1218.005", "XXXXX"
    ).replace("T1003", "XXXXX")


def test_mask_leaves_look_alikes_untouched() -> None:
    for look_alike in (
        "XT1234",
        "T12345",
        "T123",
        "ATT&CK",
        "{11111111-2222-3333-4444-555555555555}",
        "powershell.exe -NoProfile -Command Get-Process",
    ):
        assert mask_technique_ids(look_alike) == look_alike
        assert find_technique_ids(look_alike) == []


def test_has_in_band_technique_id_scans_every_string_field() -> None:
    class _Event:
        def model_dump(self) -> dict[str, object]:
            return {
                "process": {"cmd_line": r"C:\art\T1218.005\x.exe"},
                "unmapped": {"CallTrace": "ntdll.dll+9e0c0"},
            }

    class _Clean:
        def model_dump(self) -> dict[str, object]:
            return {"process": {"cmd_line": "powershell.exe -NoProfile"}}

    assert has_in_band_technique_id(_Event()) is True
    assert has_in_band_technique_id(_Clean()) is False
