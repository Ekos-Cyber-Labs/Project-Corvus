"""Chain-level ground truth for the APT29 day-1 compound dataset.

The compound file has no per-event labels, so ground truth is one
ordered chain (``eval/apt29_day1_ground_truth.json``, committed):
steps in emulation-plan order, ATT&CK technique ids per step
(``plan_techniques`` keeps the pinned plan's own ids where ATT&CK
has renamed or revoked them; ``techniques`` carries the current
ids resolved against ATT&CK v20.0 revoked-by relationships, with
any more-specific choice recorded in ``refinements`` and any
deprecated plan id with no replacement recorded in
``dropped_techniques``), a per-step window and lowercase anchors,
and the chain window
observed in the data. Event-level precision cannot be computed on
this dataset.

Step verdict (computed by ``eval/apt29_census.py``, never asserted
from the class table alone):

- ``direct``: at least one mapped event inside the step window whose
  text fields (process and parent path, command line, script
  content, file path) contain a step anchor, case-insensitive.
- ``indirect``: no mapped anchor hit, but at least one
  technique-relevant class/activity event inside the step window.
- ``none``: neither.

``match_kind`` in the chain file is the expected verdict under the
current mapping, so a mapping change that alters visibility fails
the real-file test on purpose until the expectation is updated.

Isolation: dataset name, file name, technique ids, anchors and
windows live only in the chain file, this eval code, and provenance.
They never enter an OCSF record; ``tests/test_chain_ground_truth.py``
enforces that, anchors and windows included.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CHAIN_PATH = REPO_ROOT / "eval" / "apt29_day1_ground_truth.json"

TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?$")
VERDICTS = ("direct", "indirect", "none")


def _parse_ms(text: str) -> int:
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return int(moment.astimezone(UTC).timestamp() * 1000)


def load_chain(path: Path = CHAIN_PATH) -> dict[str, Any]:
    """Load and validate the committed chain ground truth."""
    chain = json.loads(path.read_text(encoding="utf-8"))
    if chain.get("label_level") != "chain":
        raise ValueError("chain ground truth must be label_level=chain")
    if chain.get("event_level_precision_computable") is not False:
        raise ValueError("chain ground truth must declare precision not computable")
    steps = chain.get("steps")
    if not isinstance(steps, list) or [s.get("step") for s in steps] != list(
        range(1, len(steps) + 1)
    ):
        raise ValueError("chain steps must be ordered 1..n without gaps")
    chain_start, chain_end = _window_ms(chain)
    for step in steps:
        for field_name in ("techniques", "plan_techniques"):
            values = step.get(field_name)
            if not values or not all(
                isinstance(v, str) and TECHNIQUE_ID.fullmatch(v) for v in values
            ):
                raise ValueError(f"step {step.get('step')} has bad {field_name}")
        refinements = step.get("refinements")
        if not isinstance(refinements, dict):
            raise ValueError(f"step {step.get('step')} has bad refinements")
        for chosen, detail in refinements.items():
            if chosen not in step["techniques"]:
                raise ValueError(f"step {step.get('step')} refines unlisted {chosen}")
            if not isinstance(detail, dict) or not TECHNIQUE_ID.fullmatch(
                str(detail.get("refines", ""))
            ):
                raise ValueError(f"step {step.get('step')} has bad refinement base")
            if not str(detail.get("reason", "")).strip():
                raise ValueError(f"step {step.get('step')} refinement lacks a reason")
        for dropped in step.get("dropped_techniques", []):
            if not TECHNIQUE_ID.fullmatch(str(dropped.get("plan_technique", ""))):
                raise ValueError(f"step {step.get('step')} has bad dropped id")
            if (
                dropped.get("status") != "deprecated"
                or not str(dropped.get("reason", "")).strip()
            ):
                raise ValueError(f"step {step.get('step')} has bad dropped entry")
            if dropped["plan_technique"] in step["techniques"]:
                raise ValueError(f"step {step.get('step')} dropped id still listed")
        relevant = step.get("relevant")
        if not relevant or not all(
            isinstance(pair, list)
            and len(pair) == 2
            and all(isinstance(v, int) for v in pair)
            for pair in relevant
        ):
            raise ValueError(f"step {step.get('step')} has bad relevant types")
        anchors = step.get("anchors")
        if not anchors or not all(
            isinstance(a, str) and a and a == a.lower() for a in anchors
        ):
            raise ValueError(f"step {step.get('step')} has bad anchors")
        if step.get("match_kind") not in VERDICTS:
            raise ValueError(f"step {step.get('step')} has bad match_kind")
        start, end = step_window_ms(step)
        if not (chain_start <= start < end <= chain_end):
            raise ValueError(f"step {step.get('step')} window outside chain window")
    return chain


def _window_ms(chain: dict[str, Any]) -> tuple[int, int]:
    window = chain["window"]
    return _parse_ms(window["start"]), _parse_ms(window["end"])


def window_ms(chain: dict[str, Any]) -> tuple[int, int]:
    """Return the chain attack window as UTC epoch milliseconds."""
    return _window_ms(chain)


def step_window_ms(step: dict[str, Any]) -> tuple[int, int]:
    """Return one step's window as UTC epoch milliseconds."""
    window = step["window"]
    return _parse_ms(window["start"]), _parse_ms(window["end"])


def census_time_ms(event: Any) -> int:
    """Time used for step attribution: the record's ``@timestamp``.

    Step windows were derived on the ingest clock (the pinned file
    is WEF-forwarded, so Sysmon ``UtcTime`` can lag it by up to a
    minute); the OCSF ``time`` is the fallback when a record carries
    no ``@timestamp`` in ``raw_data``.
    """
    raw = getattr(event, "raw_data", None)
    if isinstance(raw, str) and raw:
        try:
            stamp = json.loads(raw).get("@timestamp")
        except ValueError:
            stamp = None
        if isinstance(stamp, str) and stamp:
            return _parse_ms(stamp)
    return int(event.time)


def event_text_fields(event: Any) -> str:
    """Lowercased anchor-search text of a mapped event.

    Process and parent path, command line, script content and file
    path only — never the whole raw record, so ingestion metadata
    cannot manufacture an anchor hit.
    """
    parts: list[str] = []

    def add_process(process: Any) -> None:
        if process is None:
            return
        parts.append(getattr(process, "name", None) or "")
        parts.append(getattr(process, "cmd_line", None) or "")
        file_obj = getattr(process, "file", None)
        parts.append(getattr(file_obj, "path", None) or "" if file_obj else "")
        add_process(getattr(process, "parent_process", None))

    add_process(getattr(event, "process", None))
    actor = getattr(event, "actor", None)
    if actor is not None:
        add_process(getattr(actor, "process", None))
    file_obj = getattr(event, "file", None)
    if file_obj is not None:
        parts.append(getattr(file_obj, "path", None) or "")
        parts.append(getattr(file_obj, "name", None) or "")
    script = getattr(event, "script", None)
    if script is not None:
        parts.append(getattr(script, "script_content", None) or "")
    return " ".join(parts).lower()


def contains_anchor(text: str, anchors: list[str]) -> bool:
    """True when ``text`` (already lowercased) contains any anchor."""
    return any(anchor in text for anchor in anchors)


def step_verdict(mapped_anchor_hits: int, relevant: int) -> str:
    """Verdict for one step from its in-window counts."""
    if mapped_anchor_hits > 0:
        return "direct"
    if relevant > 0:
        return "indirect"
    return "none"


def evaluate_mapped(events: Any, chain: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Count mapped anchor/relevant events per step (streamed).

    Returns per step ``anchor_in``, ``anchor_out`` (anchor hits in
    mapped events outside the step window), ``relevant`` (in-window
    technique-relevant class/activity events) and ``verdict``.
    Windows are per-step and disjoint hits stay disjoint: an event
    is tested against each step's own window, so the shared
    step-5/step-10 artifact cannot be counted for both steps unless
    its time fell in both windows.
    """
    counts: dict[int, dict[str, Any]] = {
        int(step["step"]): {"anchor_in": 0, "anchor_out": 0, "relevant": 0}
        for step in chain["steps"]
    }
    windows = {int(s["step"]): step_window_ms(s) for s in chain["steps"]}
    anchors = {int(s["step"]): list(s["anchors"]) for s in chain["steps"]}
    relevant = {
        int(s["step"]): {(p[0], p[1]) for p in s["relevant"]} for s in chain["steps"]
    }
    for event in events:
        time_ms = census_time_ms(event)
        text = event_text_fields(event)
        key = (getattr(event, "class_uid", None), getattr(event, "activity_id", None))
        for step_no, entry in counts.items():
            start, end = windows[step_no]
            inside = start <= time_ms <= end
            if inside and key in relevant[step_no]:
                entry["relevant"] += 1
            if text and contains_anchor(text, anchors[step_no]):
                if inside:
                    entry["anchor_in"] += 1
                else:
                    entry["anchor_out"] += 1
    for entry in counts.values():
        entry["verdict"] = step_verdict(entry["anchor_in"], entry["relevant"])
    return counts


def is_lsass_high_access(event: Any, chain: dict[str, Any]) -> bool:
    """True for a Sysmon 10 lsass open with a dumping-grade access mask.

    Keys on ``actual_permissions`` (GrantedAccess verbatim), never on
    merely touching lsass: most lsass opens are benign ``0x1000``
    queries and matching those drowns the signal in false positives.
    """
    if getattr(event, "class_uid", None) != 1007:
        return False
    if getattr(event, "activity_id", None) != 3:
        return False
    process = getattr(event, "process", None)
    name = getattr(process, "name", None) if process is not None else None
    if not isinstance(name, str) or name.lower() != "lsass.exe":
        return False
    granted = getattr(event, "actual_permissions", None)
    high = {value.lower() for value in chain.get("lsass_high_access", [])}
    return isinstance(granted, str) and granted.strip().lower() in high
