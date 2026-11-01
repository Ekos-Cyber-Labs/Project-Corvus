"""Gate-2 learning evidence: a stored rule fires on an unseen variant.

``corvus eval gate2`` builds the evidence for the learning claim —
a learned rule created from the training run detects the same
behavior in a live variant run (changed paths, tool and port, same
techniques) — and refuses a flattering report when the evidence is
not clean. Inputs are exported Wazuh data (``ossec-archive-*`` files
and/or ``alerts-*.json`` files) of two live runs of the variant
chain: one with the learned rule deployed in Wazuh (positive) and
one without it (negative control). Archives go through the existing
Linux loader (:func:`corvus.adapters.replay.linux_loader.load_linux_path`)
into temporary stores; alert files are Wazuh's own verdicts and are
read directly (rule id, groups, timestamps), never re-decided.

Learned-rule attribution uses Wazuh's own output: an alert belongs
to the rule under test when its ``rule.groups`` carry
``corvus_<sigma_rule_id>`` (the Corvus-assigned id from the rule's
lineage); any other ``corvus_*`` group, ``corvus_shadow`` group, or
rule id inside 100000-120000 marks another learned rule. Shipped
rules are everything else.

Verdict ``VALID`` needs every check clean: the four anti-leak
checks, a learned finding on every ``expected: detect`` step and on
no other step or export, zero baseline matches, and zero ledger rows
in the detection window. Anything else is ``INVALID`` with stable
codes (exit 1); malformed inputs refuse with exit 2. Coverage misses
are failures, surprises are never passes, and every number carries
its window, its n, the producing command and the git commit.

Cited-event timestamps come from the training replay store
(``--train-dir``), resolved with the real evidence loader
(:func:`corvus.llm.triage_worker.load_replay_events_by_uid`, which
returns each row's epoch-millisecond ``time``): neither the rule
lineage (uids plus backtest counts) nor the incident row (uids plus
first/last seen) carries per-event times, so there is nothing else
to resolve them from. A cited uid missing there is INVALID, never a
silent pass.

No model calls anywhere: this module never touches the network, and
it writes nothing to the database (report files only).
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "ALERT_PREFIX",
    "ARCHIVE_PREFIX",
    "CODES",
    "AlertDoc",
    "ExportData",
    "GateInputError",
    "Gate2Result",
    "GtStep",
    "NATIVE_ID_MAX",
    "NATIVE_ID_MIN",
    "main",
    "parse_ground_truth",
    "run_gate2",
]

#: Stable verdict codes. Anti-leak codes start with the report; the
#: rest gate coverage, contamination and spend.
CODES = frozenset(
    {
        "rule_created_after_variant_start",
        "lineage_training_unverifiable",
        "lineage_outside_training_windows",
        "lineage_event_unresolved",
        "lineage_uid_in_variant_export",
        "variant_specific_in_rule",
        "ledger_id_unknown",
        "ledger_after_variant_start",
        "positive_no_learned_findings",
        "swapped_positive_negative",
        "negative_control_fired",
        "missed_expected_detect",
        "surprise_detect",
        "positive_false_positive",
        "baseline_match",
        "baseline_rule_unloadable",
        "ledger_rows_in_detection_window",
    }
)

#: Learned-rule native (Wazuh) id range (same range as rule storage).
NATIVE_ID_MIN = 100000
NATIVE_ID_MAX = 120000

#: Export filename contracts (Wazuh's own names).
ALERT_PREFIX = "alerts-"
ARCHIVE_PREFIX = "ossec-archive-"

#: Values shorter than this are ignored by the variant-specific
#: screen (same floor as the backtest literal screen: a tiny
#: fragment cannot ban a legitimate selector).
MIN_TOKEN_LEN = 4


class GateInputError(ValueError):
    """A gate2 input is malformed (exit 2, no report written)."""


@dataclass(frozen=True)
class GtStep:
    """One ground-truth step window with its expectation."""

    step: int
    technique: str
    start_ms: int
    end_ms: int
    expected: str
    variant_specific: tuple[str, ...]
    desc: str

    @property
    def window_iso(self) -> str:
        """Render the step window from data timestamps."""
        return f"{format_ms(self.start_ms)}..{format_ms(self.end_ms)}"


@dataclass(frozen=True)
class AlertDoc:
    """One Wazuh alert: the SIEM's own verdict, kept verbatim."""

    time_ms: int
    rule_id: str
    groups: tuple[str, ...]
    level: int | None
    description: str


@dataclass
class ExportData:
    """One loaded variant export (archives plus alerts)."""

    name: str
    directory: Path
    archive_files: list[Path] = field(default_factory=list)
    alert_files: list[Path] = field(default_factory=list)
    ignored_files: list[str] = field(default_factory=list)
    events_total: int = 0
    alerts: list[AlertDoc] = field(default_factory=list)
    uid_to_time: dict[str, int] = field(default_factory=dict)
    window_start_ms: int | None = None
    window_end_ms: int | None = None


@dataclass
class Gate2Result:
    """The full gate outcome (report inputs, JSON-serializable)."""

    verdict: str
    codes: list[str]
    payload: dict[str, Any]

    @property
    def passed(self) -> bool:
        """True only when the verdict is VALID with no codes."""
        return self.verdict == "VALID" and not self.codes


_UTC_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_moment_ms(text: Any) -> int:
    """Parse an ISO-8601 moment (or epoch ms) to epoch milliseconds."""
    if isinstance(text, bool):
        raise GateInputError(f"not a timestamp: {text!r}")
    if isinstance(text, (int, float)):
        return int(text)
    if not isinstance(text, str) or not text.strip():
        raise GateInputError(f"not a timestamp: {text!r}")
    cleaned = text.strip()
    if cleaned.endswith(("Z", "z")):
        cleaned = cleaned[:-1] + "+00:00"
    else:
        cleaned = _UTC_OFFSET.sub(r"\1:\2", cleaned)
    try:
        moment = datetime.fromisoformat(cleaned)
    except ValueError:
        raise GateInputError(f"not a timestamp: {text!r}") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return int(moment.timestamp() * 1000)


def format_ms(moment_ms: int) -> str:
    """Format epoch milliseconds as an ISO-8601 UTC moment."""
    return datetime.fromtimestamp(moment_ms / 1000, tz=UTC).isoformat()


def parse_ground_truth(path: str | Path) -> list[GtStep]:
    """Parse a JSON-lines ground-truth file into strict step windows.

    Every line needs integer ``step`` and ISO-8601 ``start``/``end``
    (``end`` at or after ``start``). ``technique`` defaults to
    ``"unknown"``; ``expected`` defaults to ``"detect"`` and must
    otherwise be exactly ``"detect"`` or ``"miss"`` (anything else
    refuses: the report cannot classify the step); ``variant_specific``
    defaults to ``[]`` and must be a list of strings. Duplicate step
    numbers refuse. Raises :class:`GateInputError` on any violation.
    """
    steps: list[GtStep] = []
    seen: set[int] = set()
    try:
        raw_lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GateInputError(f"cannot read ground truth {path}: {exc}") from None
    for lineno, raw in enumerate(raw_lines, start=1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except ValueError as exc:
            raise GateInputError(f"{path}:{lineno}: not JSON: {exc}") from None
        if not isinstance(record, dict):
            raise GateInputError(f"{path}:{lineno}: line must be an object")
        step = record.get("step")
        if isinstance(step, bool) or not isinstance(step, int):
            raise GateInputError(f"{path}:{lineno}: step must be an integer")
        if step in seen:
            raise GateInputError(f"{path}:{lineno}: duplicate step {step}")
        seen.add(step)
        try:
            start_ms = parse_moment_ms(record.get("start"))
            end_ms = parse_moment_ms(record.get("end"))
        except GateInputError as exc:
            raise GateInputError(f"{path}:{lineno}: {exc}") from None
        if end_ms < start_ms:
            raise GateInputError(f"{path}:{lineno}: end is before start")
        technique = record.get("technique", "unknown")
        if not isinstance(technique, str) or not technique.strip():
            technique = "unknown"
        expected = record.get("expected", "detect")
        if expected not in ("detect", "miss"):
            raise GateInputError(
                f"{path}:{lineno}: unknown expected value {expected!r} "
                "(must be 'detect' or 'miss')"
            )
        variant_specific = record.get("variant_specific", [])
        if not isinstance(variant_specific, list) or any(
            not isinstance(item, str) for item in variant_specific
        ):
            raise GateInputError(
                f"{path}:{lineno}: variant_specific must be a list of strings"
            )
        desc = record.get("desc", "")
        steps.append(
            GtStep(
                step=step,
                technique=str(technique),
                start_ms=start_ms,
                end_ms=end_ms,
                expected=str(expected),
                variant_specific=tuple(variant_specific),
                desc=str(desc) if isinstance(desc, str) else "",
            )
        )
    if not steps:
        raise GateInputError(f"{path}: no steps found")
    steps.sort(key=lambda item: (item.start_ms, item.step))
    return steps


def classify_export(directory: str | Path) -> ExportData:
    """Split an export directory into archives, alerts and ignored files.

    ``alerts-*.json[.gz]`` files are Wazuh alert verdicts;
    ``ossec-archive-*`` files are raw archives; anything else (ground
    truth, notes) is ignored and reported. A missing directory, or a
    directory with neither kind, raises :class:`GateInputError`.
    """
    root = Path(directory)
    if not root.is_dir():
        raise GateInputError(f"export directory does not exist: {directory}")
    export = ExportData(name=root.name, directory=root)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in (".json", ".gz"):
            continue
        name = path.name
        if name.startswith(ALERT_PREFIX):
            export.alert_files.append(path)
        elif name.startswith(ARCHIVE_PREFIX):
            export.archive_files.append(path)
        else:
            export.ignored_files.append(path.name)
    if not export.archive_files and not export.alert_files:
        raise GateInputError(f"{directory}: no Wazuh export files found")
    return export


def _open_maybe_gz(path: Path):
    """Open a plain or gzipped JSON-lines file for text reading."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def parse_alert_file(path: Path) -> list[AlertDoc]:
    """Parse one Wazuh alert file into strict alert verdicts.

    Blank lines are skipped; any other line must be a JSON object
    with a parseable ``timestamp`` and a ``rule`` block carrying an
    ``id``. ``groups`` defaults to ``[]``; ``level`` and
    ``description`` default to unknown/empty. Raises
    :class:`GateInputError` on the first malformed line.
    """
    alerts: list[AlertDoc] = []
    try:
        handle = _open_maybe_gz(path)
    except OSError as exc:
        raise GateInputError(f"cannot read alert file {path}: {exc}") from None
    with handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                doc = json.loads(raw)
            except ValueError as exc:
                raise GateInputError(f"{path}:{lineno}: not JSON: {exc}") from None
            if not isinstance(doc, dict):
                raise GateInputError(f"{path}:{lineno}: alert must be an object")
            try:
                time_ms = parse_moment_ms(doc.get("timestamp"))
            except GateInputError as exc:
                raise GateInputError(f"{path}:{lineno}: {exc}") from None
            rule = doc.get("rule")
            if not isinstance(rule, dict) or rule.get("id") is None:
                raise GateInputError(f"{path}:{lineno}: alert has no rule id")
            groups = rule.get("groups", [])
            if not isinstance(groups, list) or any(
                not isinstance(item, str) for item in groups
            ):
                raise GateInputError(f"{path}:{lineno}: rule groups must be strings")
            level = rule.get("level")
            if level is not None and (
                isinstance(level, bool) or not isinstance(level, int)
            ):
                raise GateInputError(f"{path}:{lineno}: rule level must be an integer")
            description = rule.get("description", "")
            alerts.append(
                AlertDoc(
                    time_ms=time_ms,
                    rule_id=str(rule.get("id")),
                    groups=tuple(groups),
                    level=level,
                    description=str(description)
                    if isinstance(description, str)
                    else "",
                )
            )
    return alerts


def load_export_archives(
    export: ExportData, store_dir: str | Path, *, data_dir: str | Path = "data"
) -> None:
    """Load an export's archives into a temporary store (existing loader).

    Each ``ossec-archive-*`` file goes through
    :func:`corvus.adapters.replay.linux_loader.load_linux_path` on
    its own (so one bad file cannot hide behind another); the store
    gains the uid-to-time index and the data window for the report.
    """
    from corvus.adapters.replay.linux_loader import load_linux_path

    for path in export.archive_files:
        try:
            summary = load_linux_path(path, replay_dir=store_dir, data_dir=data_dir)
        except ValueError as exc:
            raise GateInputError(f"cannot load archive {path}: {exc}") from None
        export.events_total += summary.events_total
    index, window = read_store_index(store_dir)
    export.uid_to_time = index
    if window is not None:
        export.window_start_ms, export.window_end_ms = window


def read_store_index(
    store_dir: str | Path,
) -> tuple[dict[str, int], tuple[int, int] | None]:
    """Read the uid-to-time index plus the data window of a store.

    Returns ``(uid_to_time, (min_ms, max_ms) or None)``; an empty
    store yields an empty index and no window (never raises).
    """
    import glob

    import pyarrow.parquet as pq

    index: dict[int, int] = {}
    times: list[int] = []
    pattern = str(Path(store_dir) / "events" / "*.parquet")
    for path in sorted(glob.glob(pattern)):
        try:
            table = pq.read_table(path, columns=["uid", "time"])
        except OSError, ValueError:
            continue
        for row in table.to_pylist():
            uid = row.get("uid")
            moment = row.get("time")
            if isinstance(uid, str) and isinstance(moment, int):
                index[uid] = moment
                times.append(moment)
    if not times:
        return {}, None
    return index, (min(times), max(times))


def _is_learned_alert(alert: AlertDoc) -> bool:
    """True when Wazuh marked the alert as a learned (Corvus) rule."""
    if "corvus_shadow" in alert.groups:
        return True
    if any(group.startswith("corvus_") for group in alert.groups):
        return True
    try:
        native = int(alert.rule_id)
    except ValueError:
        return False
    return NATIVE_ID_MIN <= native <= NATIVE_ID_MAX


def split_alerts(
    alerts: list[AlertDoc], *, sigma_rule_id: str
) -> tuple[list[AlertDoc], list[AlertDoc], list[AlertDoc]]:
    """Split alerts into (mine, other-learned, shipped) for one rule.

    ``mine`` carries the rule's own ``corvus_<sigma id>`` group (the
    Corvus-assigned id Wazuh deploys under); a bare native-id match
    without the group counts as other-learned, never mine, so a
    reallocated native id cannot credit the wrong rule.
    ``other-learned`` is any remaining Corvus-marked or native-range
    alert; ``shipped`` is everything else.
    """
    marker = f"corvus_{sigma_rule_id}"
    mine: list[AlertDoc] = []
    other: list[AlertDoc] = []
    shipped: list[AlertDoc] = []
    for alert in alerts:
        if marker in alert.groups:
            mine.append(alert)
        elif _is_learned_alert(alert):
            other.append(alert)
        else:
            shipped.append(alert)
    return mine, other, shipped


def in_window(alert: AlertDoc, step: GtStep) -> bool:
    """True when the alert falls in the step window (inclusive)."""
    return step.start_ms <= alert.time_ms <= step.end_ms


def _to_ms(moment: Any) -> int:
    """Render an aware datetime as epoch milliseconds."""
    if getattr(moment, "tzinfo", None) is None:
        moment = moment.replace(tzinfo=UTC)
    return int(moment.timestamp() * 1000)


def fetch_rule(database_url: str, rule_id: int) -> dict[str, Any]:
    """Return the stored rule row or raise :class:`GateInputError`."""
    from corvus.learning.rules import get_rule

    row = get_rule(database_url, rule_id)
    if row is None:
        raise GateInputError(f"unknown rule id {rule_id}")
    return row


def fetch_incident_uids(database_url: str, incident_id: int) -> list[str] | None:
    """Return the incident's event uids, or None when the row is gone."""
    import psycopg

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_uids FROM incidents WHERE id = %s", (incident_id,)
            )
            row = cur.fetchone()
    if row is None:
        return None
    return [str(item) for item in (row[0] or [])]


def fetch_attempt_times(database_url: str, attempt_ids: list[int]) -> dict[int, int]:
    """Map llm_attempt ids to created_at ms (missing ids stay absent)."""
    import psycopg

    if not attempt_ids:
        return {}
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, created_at FROM llm_attempts WHERE id = ANY(%s)",
                (list(attempt_ids),),
            )
            rows = cur.fetchall() or []
    return {int(row[0]): _to_ms(row[1]) for row in rows}


def ledger_segments(
    database_url: str, start_ms: int, end_ms: int | None
) -> dict[str, Any]:
    """Split ledger rows into before/in/after the detection window.

    The window is ``[start_ms, end_ms]`` inclusive on both ends (a
    model row stamped exactly at the last finding still counts as
    detection spend). ``end_ms`` None means the last finding is
    unknown: every row lands in ``before``/``after`` by ``start_ms``.
    Groups mirror ``corvus rules ledger-check`` (purpose/model).
    """

    def grouped(
        rows: list[tuple[str, str, int]],
    ) -> dict[str, Any]:
        by_purpose: dict[tuple[str, str], int] = {}
        for purpose, model, _ in rows:
            by_purpose[(purpose, model)] = by_purpose.get((purpose, model), 0) + 1
        return {
            "rows": len(rows),
            "by_purpose_model": [
                {"purpose": purpose, "model": model, "rows": count}
                for (purpose, model), count in sorted(by_purpose.items())
            ],
        }

    import psycopg

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT purpose, model, created_at FROM llm_attempts ORDER BY id"
            )
            attempts = [
                (str(row[0]), str(row[1]), _to_ms(row[2]))
                for row in (cur.fetchall() or [])
            ]
            cur.execute("SELECT model, usd, created_at FROM spend ORDER BY id")
            spend = [
                (str(row[0]), float(row[1]), _to_ms(row[2]))
                for row in (cur.fetchall() or [])
            ]
    before_a = [row for row in attempts if row[2] < start_ms]
    before_s = [row for row in spend if row[2] < start_ms]
    if end_ms is None:
        after_a = [row for row in attempts if row[2] >= start_ms]
        after_s = [row for row in spend if row[2] >= start_ms]
        inside_a: list[Any] = []
        inside_s: list[Any] = []
    else:
        inside_a = [row for row in attempts if start_ms <= row[2] <= end_ms]
        inside_s = [row for row in spend if start_ms <= row[2] <= end_ms]
        after_a = [row for row in attempts if row[2] > end_ms]
        after_s = [row for row in spend if row[2] > end_ms]
    return {
        "before": {
            "attempts": grouped([(p, m, t) for p, m, t in before_a]),
            "spend_rows": len(before_s),
            "spend_usd": round(sum(usd for _, usd, _ in before_s), 6),
        },
        "inside": {
            "attempts": grouped([(p, m, t) for p, m, t in inside_a]),
            "spend_rows": len(inside_s),
            "spend_usd": round(sum(usd for _, usd, _ in inside_s), 6),
        },
        "after": {
            "attempts": grouped([(p, m, t) for p, m, t in after_a]),
            "spend_rows": len(after_s),
            "spend_usd": round(sum(usd for _, usd, _ in after_s), 6),
        },
    }


def resolve_cited_times(train_dir: str | Path, cited: list[str]) -> dict[str, int]:
    """Resolve cited event uids to epoch-ms timestamps from the store.

    Uses the real evidence loader
    (:func:`corvus.llm.triage_worker.load_replay_events_by_uid`),
    whose rows carry each event's epoch-millisecond ``time``. Uids
    the store does not hold stay absent (the caller treats that as
    INVALID, never a pass). Raises :class:`GateInputError` when
    ``train_dir`` is no usable replay store.
    """
    from corvus.llm.triage_worker import load_replay_events_by_uid

    root = Path(train_dir)
    if not root.is_dir() or not list((root / "events").glob("*.parquet")):
        raise GateInputError(f"{train_dir}: no training replay store found")
    rows = load_replay_events_by_uid(root, cited)
    times: dict[str, int] = {}
    for row in rows:
        uid = row.get("event_uid")
        moment = row.get("time")
        if isinstance(uid, str) and isinstance(moment, int) and uid not in times:
            times[uid] = moment
    return times


def anti_leak_checks(
    *,
    rule: dict[str, Any],
    train_text: str,
    train_steps: list[GtStep],
    train_times: dict[str, int],
    variant_steps: list[GtStep],
    variant_uids: dict[str, int],
    database_url: str,
    sigma_text: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Run the four anti-leak checks; return (codes, check rows).

    ``train_times`` maps every cited event uid to its epoch-ms
    timestamp resolved from the training replay store (see
    :func:`resolve_cited_times`); ``variant_uids`` maps event uids
    found in either variant export to their export timestamps;
    ``variant_steps`` unions both variant ground truths. Cited
    timestamps are compared against the ``--train-gt`` step windows
    for real (inclusive): an unresolvable or out-of-window cited
    event is INVALID.
    """
    codes: list[str] = []
    rows: list[dict[str, Any]] = []
    lineage = rule.get("lineage") or {}
    created_ms = _to_ms(rule["created_at"])
    variant_start = min(step.start_ms for step in variant_steps)
    variant_windows = [(step.start_ms, step.end_ms) for step in variant_steps]
    train_windows = [(step.start_ms, step.end_ms) for step in train_steps]

    if created_ms < variant_start:
        rows.append(
            {
                "check": "a-created-before-variant",
                "result": "PASS",
                "detail": f"rule created {format_ms(created_ms)} before "
                f"first variant step {format_ms(variant_start)}",
            }
        )
    else:
        codes.append("rule_created_after_variant_start")
        rows.append(
            {
                "check": "a-created-before-variant",
                "result": "FAIL",
                "detail": f"rule created {format_ms(created_ms)} at/after "
                f"first variant step {format_ms(variant_start)}",
            }
        )

    cited = lineage.get("cited_uids", [])
    if not isinstance(cited, list) or any(not isinstance(uid, str) for uid in cited):
        codes.append("lineage_training_unverifiable")
        rows.append(
            {
                "check": "b-lineage-cited-in-backtest",
                "result": "FAIL",
                "detail": "lineage cited_uids is not a string list",
            }
        )
        cited = []
    elif not cited:
        rows.append(
            {
                "check": "b-lineage-cited-in-backtest",
                "result": "PASS",
                "detail": "no cited events recorded (nothing to leak)",
            }
        )
    else:
        backtest = lineage.get("backtest")
        matched = (
            set(backtest.get("target_matched", []))
            if isinstance(backtest, dict)
            and backtest.get("codes") == ["accepted"]
            and isinstance(backtest.get("target_matched"), list)
            else None
        )
        missing = (
            [uid for uid in cited if uid not in matched]
            if matched is not None
            else list(cited)
        )
        if missing:
            codes.append("lineage_training_unverifiable")
            rows.append(
                {
                    "check": "b-lineage-cited-in-backtest",
                    "result": "FAIL",
                    "detail": f"n={len(missing)} cited uid(s) missing from the "
                    "recorded accepted backtest target_matched",
                    "uids": missing,
                }
            )
        else:
            rows.append(
                {
                    "check": "b-lineage-cited-in-backtest",
                    "result": "PASS",
                    "detail": f"n={len(cited)} cited uid(s) all in the recorded "
                    f"accepted backtest target_matched (n={len(matched or [])})",
                }
            )
    if cited:
        unresolved = [uid for uid in cited if uid not in train_times]
        outside = [
            uid
            for uid in cited
            if uid in train_times
            and not any(s <= train_times[uid] <= e for s, e in train_windows)
        ]
        if unresolved:
            codes.append("lineage_event_unresolved")
        if outside:
            codes.append("lineage_outside_training_windows")
        if unresolved or outside:
            rows.append(
                {
                    "check": "b-lineage-in-training-windows",
                    "result": "FAIL",
                    "detail": f"n={len(cited)} cited event(s) against "
                    f"n={len(train_windows)} training window(s) "
                    f"({format_ms(min(s for s, _ in train_windows))}.."
                    f"{format_ms(max(e for _, e in train_windows))}): "
                    f"n={len(unresolved)} unresolvable in the training "
                    f"store, n={len(outside)} outside every window",
                    "unresolved_uids": sorted(unresolved),
                    "outside_uids": sorted(outside),
                }
            )
        else:
            rows.append(
                {
                    "check": "b-lineage-in-training-windows",
                    "result": "PASS",
                    "detail": f"n={len(cited)} cited event(s), each resolved "
                    "in the training store inside a --train-gt step window "
                    f"(n={len(train_windows)} windows, "
                    f"{format_ms(min(s for s, _ in train_windows))}.."
                    f"{format_ms(max(e for _, e in train_windows))})",
                }
            )
    else:
        rows.append(
            {
                "check": "b-lineage-in-training-windows",
                "result": "PASS",
                "detail": "no cited events recorded (nothing to place)",
            }
        )
    leaked = [uid for uid in cited if uid in variant_uids] if cited else []
    if leaked:
        codes.append("lineage_uid_in_variant_export")
        inside = [
            uid
            for uid in leaked
            if any(s <= variant_uids[uid] <= e for s, e in variant_windows)
        ]
        rows.append(
            {
                "check": "b-lineage-outside-variant-windows",
                "result": "FAIL",
                "detail": f"n={len(leaked)} cited uid(s) present in a variant "
                f"export (n={len(inside)} inside a variant step window)",
                "uids": sorted(leaked),
            }
        )
    else:
        rows.append(
            {
                "check": "b-lineage-outside-variant-windows",
                "result": "PASS",
                "detail": f"n={len(cited)} cited uid(s), none present in either "
                "variant export",
            }
        )

    declared: set[str] = set()
    for step in variant_steps:
        declared.update(step.variant_specific)
    variant_only = [
        value
        for value in declared
        if len(value) >= MIN_TOKEN_LEN and value.lower() not in train_text.lower()
    ]
    hits = [value for value in variant_only if value.lower() in sigma_text.lower()]
    if hits:
        codes.append("variant_specific_in_rule")
        rows.append(
            {
                "check": "c-no-variant-values-in-rule",
                "result": "FAIL",
                "detail": f"n={len(hits)} variant-only value(s) in the detection text",
                "values": sorted(hits),
            }
        )
    else:
        rows.append(
            {
                "check": "c-no-variant-values-in-rule",
                "result": "PASS",
                "detail": f"n={len(variant_only)} variant-only declared value(s) "
                f"checked (n={len(declared)} declared), none in the text",
            }
        )

    ledger_ids = lineage.get("ledger_ids")
    if ledger_ids is None or ledger_ids == []:
        rows.append(
            {
                "check": "d-model-never-saw-variant",
                "result": "PASS",
                "detail": "no ledger ids recorded (non-model provenance: "
                "nothing billable could have seen variant data)",
            }
        )
    elif not isinstance(ledger_ids, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in ledger_ids
    ):
        codes.append("ledger_id_unknown")
        rows.append(
            {
                "check": "d-model-never-saw-variant",
                "result": "FAIL",
                "detail": "lineage ledger_ids is not an integer list",
            }
        )
    else:
        times = fetch_attempt_times(database_url, list(ledger_ids))
        unknown = [item for item in ledger_ids if item not in times]
        late = [item for item in ledger_ids if times.get(item, -1) >= variant_start]
        if unknown:
            codes.append("ledger_id_unknown")
        if late:
            codes.append("ledger_after_variant_start")
        if unknown or late:
            rows.append(
                {
                    "check": "d-model-never-saw-variant",
                    "result": "FAIL",
                    "detail": f"n={len(ledger_ids)} recorded attempt(s): "
                    f"n={len(unknown)} unknown in llm_attempts, "
                    f"n={len(late)} at/after first variant step "
                    f"{format_ms(variant_start)}",
                    "late_ids": sorted(late),
                    "unknown_ids": sorted(unknown),
                }
            )
        else:
            rows.append(
                {
                    "check": "d-model-never-saw-variant",
                    "result": "PASS",
                    "detail": f"n={len(ledger_ids)} recorded attempt(s), all "
                    f"created before first variant step "
                    f"{format_ms(variant_start)}",
                }
            )
    return codes, rows


REPO_ROOT = Path(__file__).resolve().parent.parent


def git_commit() -> str:
    """Return the current HEAD commit, or ``unknown`` off-repo."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError, subprocess.SubprocessError:
        return "unknown"
    commit = out.stdout.strip()
    return commit if commit else "unknown"


def git_dirty() -> tuple[bool, int]:
    """Return (dirty, changed-path count) for the working tree."""
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError, subprocess.SubprocessError:
        return False, 0
    if out.returncode != 0:
        return False, 0
    paths = [line for line in out.stdout.splitlines() if line.strip()]
    return bool(paths), len(paths)


def _resolve_baseline_store(
    baseline_dir: str | Path, workdir: Path, *, data_dir: str | Path
) -> tuple[Path, dict[str, Any]]:
    """Return ``(store_dir, note)`` for the baseline (store or export).

    A directory already holding ``events/*.parquet`` is used as-is
    (the committed baseline store); otherwise its ``ossec-archive-*``
    files are loaded into a temporary store with the existing
    loader. Alert files in a baseline export play no role and are
    reported as ignored.
    """
    root = Path(baseline_dir)
    if not root.is_dir():
        raise GateInputError(f"baseline directory does not exist: {baseline_dir}")
    if list((root / "events").glob("*.parquet")):
        return root, {"mode": "store", "alert_files_ignored": 0}
    export = classify_export(str(root))
    if not export.archive_files:
        raise GateInputError(f"{baseline_dir}: no baseline store or archives found")
    store = workdir / "baseline"
    store.mkdir(parents=True, exist_ok=True)
    load_export_archives(export, store, data_dir=data_dir)
    return store, {
        "mode": "export-loaded",
        "alert_files_ignored": len(export.alert_files),
        "ignored_files": sorted(export.ignored_files),
    }


def baseline_rule_matches(
    sigma_text: str, sigma_rule_id: str, store_dir: str | Path
) -> dict[str, Any]:
    """Evaluate the stored rule over the baseline store (same engine).

    The stored text compiles through the shipped-rule loader (all
    statuses: the stored copy is ``experimental`` by design) and runs
    through :func:`corvus.detect.engine.evaluate`, exactly like the
    backtest. Returns counts plus the matched uids (hashes, never
    raw events). A rule that no longer compiles reports
    ``unloadable`` instead of a zero.
    """
    from corvus.detect.engine import evaluate
    from corvus.detect.rules import ALL_STATUSES, load_rules

    with tempfile.TemporaryDirectory(prefix="gate2-baseline-rule") as tmp:
        candidate = Path(tmp) / "candidate.yml"
        candidate.write_text(sigma_text, encoding="utf-8")
        try:
            compiled, _stats = load_rules(Path(tmp), statuses=ALL_STATUSES)
        except Exception as exc:
            return {"unloadable": f"{type(exc).__name__}: {exc}"}
    items = [item for item in compiled if item.rule_id == sigma_rule_id]
    if not items:
        return {"unloadable": "stored rule did not compile (skipped by loader)"}
    matches, _infos, stats = evaluate(store_dir, items)
    matched = sorted(matches.get(sigma_rule_id, set()))
    index, window = read_store_index(store_dir)
    return {
        "matches": matched,
        "events_total": len(index),
        "window": [format_ms(window[0]), format_ms(window[1])]
        if window is not None
        else None,
        "events_scanned": stats.events_scanned,
    }


def _step_row(
    step: GtStep,
    mine: list[AlertDoc],
    shipped: list[AlertDoc],
    *,
    rule_db_id: int,
    rule_version: int,
) -> dict[str, Any]:
    """Build one step's observed-vs-expected row for the report."""
    in_learned = sorted(
        [alert for alert in mine if in_window(alert, step)],
        key=lambda alert: alert.time_ms,
    )
    in_shipped: dict[str, int] = {}
    for alert in shipped:
        if in_window(alert, step):
            in_shipped[alert.rule_id] = in_shipped.get(alert.rule_id, 0) + 1
    delay: float | None = None
    if in_learned:
        delay = round((in_learned[0].time_ms - step.start_ms) / 1000, 1)
    if step.expected == "detect":
        verdict = "PASS" if in_learned else "FAIL"
    else:
        verdict = "SURPRISE" if in_learned else "PASS"
    return {
        "step": step.step,
        "technique": step.technique,
        "window": step.window_iso,
        "expected": step.expected,
        "learned_n": len(in_learned),
        "first_delay_s": delay,
        "rule_db_id": rule_db_id,
        "rule_version": rule_version,
        "shipped": dict(sorted(in_shipped.items())),
        "verdict": verdict,
    }


def run_gate2(
    *,
    database_url: str,
    rule_id: int,
    train_gt: str | Path,
    positive: str | Path,
    positive_gt: str | Path,
    negative: str | Path,
    negative_gt: str | Path,
    baseline_dir: str | Path = "data/replay-linux-baseline",
    train_dir: str | Path = "data/replay-linux-chain1",
    data_dir: str | Path = "data",
    producing_command: str = "",
    commit: str = "unknown",
    dirty_tree: bool = False,
    dirty_paths_n: int = 0,
) -> Gate2Result:
    """Run gate 2 end to end; return the verdict plus the report payload.

    Raises :class:`GateInputError` for malformed inputs (no report).
    Everything else — including every INVALID cause — lands in the
    returned payload so the report can show it.
    """
    rule = fetch_rule(database_url, rule_id)
    lineage = rule.get("lineage") or {}
    sigma_rule_id = lineage.get("sigma_rule_id")
    if not isinstance(sigma_rule_id, str) or not sigma_rule_id:
        raise GateInputError(f"rule {rule_id} has no sigma id in its lineage")
    sigma_text = rule.get("sigma_text") or ""
    if not isinstance(sigma_text, str) or not sigma_text.strip():
        raise GateInputError(f"rule {rule_id} has no detection text")
    try:
        train_text = Path(train_gt).read_text(encoding="utf-8")
    except OSError as exc:
        raise GateInputError(f"cannot read train ground truth: {exc}") from None
    train_steps = parse_ground_truth(train_gt)
    pos_steps = parse_ground_truth(positive_gt)
    neg_steps = parse_ground_truth(negative_gt)
    variant_steps = pos_steps + neg_steps
    variant_start = min(step.start_ms for step in variant_steps)

    with tempfile.TemporaryDirectory(prefix="gate2-") as work:
        workdir = Path(work)
        pos_export = classify_export(positive)
        neg_export = classify_export(negative)
        for export in (pos_export, neg_export):
            for alert_path in export.alert_files:
                export.alerts.extend(parse_alert_file(alert_path))
            store = workdir / f"store-{export.name}"
            store.mkdir(parents=True, exist_ok=True)
            load_export_archives(export, store, data_dir=data_dir)
            if not export.alerts and export.events_total == 0:
                raise GateInputError(f"{export.directory}: export is empty")
        base_store, base_note = _resolve_baseline_store(
            baseline_dir, workdir, data_dir=data_dir
        )

        pos_mine, pos_other, pos_shipped = split_alerts(
            pos_export.alerts, sigma_rule_id=sigma_rule_id
        )
        neg_mine, neg_other, neg_shipped = split_alerts(
            neg_export.alerts, sigma_rule_id=sigma_rule_id
        )

        codes: list[str] = []
        if neg_mine:
            codes.append("negative_control_fired")
            if not pos_mine:
                codes.append("swapped_positive_negative")
        elif not pos_mine:
            codes.append("positive_no_learned_findings")

        pos_rows = [
            _step_row(
                step,
                pos_mine,
                pos_shipped,
                rule_db_id=int(rule["id"]),
                rule_version=int(rule["version"]),
            )
            for step in pos_steps
        ]
        if any(row["verdict"] == "FAIL" for row in pos_rows):
            codes.append("missed_expected_detect")
        if any(row["verdict"] == "SURPRISE" for row in pos_rows):
            codes.append("surprise_detect")
        pos_fp = sorted(
            [
                alert
                for alert in pos_mine
                if not any(in_window(alert, step) for step in pos_steps)
            ],
            key=lambda alert: alert.time_ms,
        )
        if pos_fp:
            codes.append("positive_false_positive")

        neg_rows = [
            _step_row(
                step,
                neg_mine,
                neg_shipped,
                rule_db_id=int(rule["id"]),
                rule_version=int(rule["version"]),
            )
            for step in neg_steps
        ]

        variant_uids = dict(pos_export.uid_to_time)
        variant_uids.update(neg_export.uid_to_time)
        raw_cited = lineage.get("cited_uids", [])
        cited_list = (
            [uid for uid in raw_cited if isinstance(uid, str)]
            if isinstance(raw_cited, list)
            else []
        )
        train_times = resolve_cited_times(train_dir, cited_list) if cited_list else {}
        leak_codes, leak_rows = anti_leak_checks(
            rule=rule,
            train_text=train_text,
            train_steps=train_steps,
            train_times=train_times,
            variant_steps=variant_steps,
            variant_uids=variant_uids,
            database_url=database_url,
            sigma_text=sigma_text,
        )
        codes.extend(leak_codes)

        base_result = baseline_rule_matches(sigma_text, sigma_rule_id, base_store)
        if "unloadable" in base_result:
            codes.append("baseline_rule_unloadable")
        elif base_result["matches"]:
            codes.append("baseline_match")

        last_find_ms = max((alert.time_ms for alert in pos_mine), default=None)
        segments = ledger_segments(database_url, variant_start, last_find_ms)
        if segments["inside"]["attempts"]["rows"] or segments["inside"]["spend_rows"]:
            codes.append("ledger_rows_in_detection_window")

        return _assemble(
            rule=rule,
            sigma_rule_id=sigma_rule_id,
            codes=codes,
            leak_rows=leak_rows,
            train_steps=train_steps,
            pos_steps=pos_steps,
            neg_steps=neg_steps,
            pos_export=pos_export,
            neg_export=neg_export,
            pos_mine=pos_mine,
            pos_other=pos_other,
            pos_shipped=pos_shipped,
            neg_mine=neg_mine,
            neg_other=neg_other,
            neg_shipped=neg_shipped,
            pos_rows=pos_rows,
            neg_rows=neg_rows,
            pos_fp=pos_fp,
            base_result=base_result,
            base_note=base_note,
            baseline_dir=str(baseline_dir),
            segments=segments,
            variant_start=variant_start,
            last_find_ms=last_find_ms,
            database_url=database_url,
            producing_command=producing_command,
            commit=commit,
            dirty_tree=dirty_tree,
            dirty_paths_n=dirty_paths_n,
            inputs={
                "train_gt": str(train_gt),
                "positive": str(positive),
                "positive_gt": str(positive_gt),
                "negative": str(negative),
                "negative_gt": str(negative_gt),
            },
        )


def _distinct_learned(
    mine: list[AlertDoc], other: list[AlertDoc], sigma_rule_id: str
) -> dict[str, Any]:
    """Count distinct learned rules behind the mine/other alerts.

    One other alert is one identity: its ``corvus_<suffix>`` group
    when present, else its native-range rule id (so an alert carrying
    both is never counted twice).
    """
    others: set[str] = set()
    for alert in other:
        suffixes = [
            group.removeprefix("corvus_")
            for group in alert.groups
            if group.startswith("corvus_") and group != "corvus_shadow"
        ]
        if suffixes:
            others.update(f"group:{suffix}" for suffix in suffixes)
        else:
            try:
                native = int(alert.rule_id)
            except ValueError:
                continue
            if NATIVE_ID_MIN <= native <= NATIVE_ID_MAX:
                others.add(f"native:{alert.rule_id}")
    return {
        "n": (1 if (mine or other) else 0) + len(others),
        "mine_sigma_id": sigma_rule_id,
        "other_ids": sorted(others),
    }


def _technique_sequence(steps: list[GtStep]) -> list[str]:
    """Return the ordered technique per step (behavior fingerprint)."""
    return [f"{step.step}:{step.technique}" for step in steps]


def _assemble(
    *,
    rule: dict[str, Any],
    sigma_rule_id: str,
    codes: list[str],
    leak_rows: list[dict[str, Any]],
    train_steps: list[GtStep],
    pos_steps: list[GtStep],
    neg_steps: list[GtStep],
    pos_export: ExportData,
    neg_export: ExportData,
    pos_mine: list[AlertDoc],
    pos_other: list[AlertDoc],
    pos_shipped: list[AlertDoc],
    neg_mine: list[AlertDoc],
    neg_other: list[AlertDoc],
    neg_shipped: list[AlertDoc],
    pos_rows: list[dict[str, Any]],
    neg_rows: list[dict[str, Any]],
    pos_fp: list[AlertDoc],
    base_result: dict[str, Any],
    base_note: dict[str, Any],
    baseline_dir: str,
    segments: dict[str, Any],
    variant_start: int,
    last_find_ms: int | None,
    database_url: str,
    producing_command: str,
    commit: str,
    dirty_tree: bool,
    dirty_paths_n: int,
    inputs: dict[str, str],
) -> Gate2Result:
    """Build the verdict and the full report payload from gate outputs."""
    lineage = rule.get("lineage") or {}
    cited = lineage.get("cited_uids", [])
    source_incident = lineage.get("source_incident")
    if isinstance(source_incident, int):
        incident_uids = fetch_incident_uids(database_url, source_incident)
        training_set: dict[str, Any] = {
            "incidents_n": 1,
            "incident_id": source_incident,
            "incident_events_n": len(incident_uids)
            if incident_uids is not None
            else None,
            "incident_events_note": "incident row gone (ON DELETE SET NULL)"
            if incident_uids is None
            else None,
            "cited_events_n": len(cited) if isinstance(cited, list) else 0,
        }
    else:
        training_set = {
            "incidents_n": 0,
            "incident_id": None,
            "incident_events_n": None,
            "incident_events_note": "no source incident recorded",
            "cited_events_n": len(cited) if isinstance(cited, list) else 0,
        }
    declared = sorted(
        {value for step in pos_steps + neg_steps for value in step.variant_specific}
    )
    train_seq = _technique_sequence(train_steps)
    pos_seq = _technique_sequence(pos_steps)
    neg_seq = _technique_sequence(neg_steps)
    verdict = "INVALID" if codes else "VALID"
    payload: dict[str, Any] = {
        "meta": {
            "producing_command": producing_command,
            "git_commit": commit,
            "dirty_tree": dirty_tree,
            "dirty_paths_n": dirty_paths_n,
            "verdict": verdict,
            "codes": sorted(set(codes)),
            "rule": {
                "db_id": int(rule["id"]),
                "sigma_rule_id": sigma_rule_id,
                "version": int(rule["version"]),
                "title": str(rule.get("title") or ""),
                "status": str(rule.get("status") or ""),
                "native_rule_id": rule.get("native_rule_id"),
                "created_at": rule["created_at"].isoformat(),
            },
            "variant_window": {
                "start": format_ms(variant_start),
                "end": format_ms(max(step.end_ms for step in pos_steps + neg_steps)),
            },
        },
        "inputs": inputs,
        "anti_leak": leak_rows,
        "positive": {
            "dir": str(pos_export.directory),
            "n_events": pos_export.events_total,
            "n_alerts": len(pos_export.alerts),
            "n_alert_files": len(pos_export.alert_files),
            "n_archive_files": len(pos_export.archive_files),
            "ignored_files": sorted(pos_export.ignored_files),
            "data_window": [
                format_ms(pos_export.window_start_ms),
                format_ms(pos_export.window_end_ms),
            ]
            if pos_export.window_start_ms is not None
            and pos_export.window_end_ms is not None
            else None,
            "steps": pos_rows,
            "learned_n": len(pos_mine),
            "other_learned_n": len(pos_other),
            "shipped_n": len(pos_shipped),
            "false_positives": [
                {"time": format_ms(alert.time_ms), "rule_id": alert.rule_id}
                for alert in pos_fp
            ],
        },
        "negative": {
            "dir": str(neg_export.directory),
            "n_events": neg_export.events_total,
            "n_alerts": len(neg_export.alerts),
            "n_alert_files": len(neg_export.alert_files),
            "n_archive_files": len(neg_export.archive_files),
            "ignored_files": sorted(neg_export.ignored_files),
            "data_window": [
                format_ms(neg_export.window_start_ms),
                format_ms(neg_export.window_end_ms),
            ]
            if neg_export.window_start_ms is not None
            and neg_export.window_end_ms is not None
            else None,
            "steps": neg_rows,
            "learned_n": len(neg_mine),
            "learned_times": [format_ms(alert.time_ms) for alert in neg_mine],
            "other_learned_n": len(neg_other),
            "shipped_n": len(neg_shipped),
        },
        "baseline": {
            "dir": baseline_dir,
            "mode": base_note.get("mode"),
            "n_events": base_result.get("events_total"),
            "window": base_result.get("window"),
            "matches_n": len(base_result.get("matches", [])),
            "match_uids": base_result.get("matches", []),
            "unloadable": base_result.get("unloadable"),
        },
        "ledger": {
            "detection_window": {
                "start": format_ms(variant_start),
                "end": format_ms(last_find_ms) if last_find_ms is not None else None,
            },
            "segments": segments,
        },
        "limits": {
            "expected_miss_missed": [
                row["step"]
                for row in pos_rows
                if row["expected"] == "miss" and row["verdict"] == "PASS"
            ],
            "expected_detect_missed": [
                row["step"] for row in pos_rows if row["verdict"] == "FAIL"
            ],
            "uncovered_by_any_rule": [
                row["step"]
                for row in pos_rows
                if row["learned_n"] == 0 and not row["shipped"]
            ],
            "distinct_learned_rules": _distinct_learned(
                pos_mine, pos_other, sigma_rule_id
            ),
            "training_set": training_set,
            "train_techniques": train_seq,
            "positive_techniques": pos_seq,
            "negative_techniques": neg_seq,
            "behavior_same_as_training": train_seq == pos_seq == neg_seq,
            "variant_specific_declared_n": len(declared),
            "variant_specific_declared": declared,
            "no_model_weight_updates": (
                "No model weights are updated anywhere in this pipeline: "
                "what is learned is a verified, versioned Sigma rule "
                "(see the rule-proposal loop, which stores text plus "
                "lineage, never gradients)."
            ),
        },
    }
    ordered = sorted(set(codes))
    return Gate2Result(verdict=verdict, codes=ordered, payload=payload)


def _fmt_delay(value: float | None) -> str:
    """Render a first-detection delay for the step table."""
    return f"{value:.1f} s" if value is not None else "-"


def render_markdown(result: Gate2Result) -> str:
    """Render ``eval/reports/gate2.md`` (every number with window and n)."""
    payload = result.payload
    meta = payload["meta"]
    pos = payload["positive"]
    neg = payload["negative"]
    base = payload["baseline"]
    ledger = payload["ledger"]
    limits = payload["limits"]
    rule = meta["rule"]
    lines = [
        f"# Gate 2 — learned-rule variant evidence: {meta['verdict']}",
        "",
        f"Producing command: `{meta['producing_command']}` (n = 1 run, "
        f"git commit `{meta['git_commit']}`).",
        f"Variant window: {meta['variant_window']['start']} to "
        f"{meta['variant_window']['end']} "
        f"(n={len(pos['steps']) + len(neg['steps'])} steps across both "
        "variant ground truths; every timestamp below is data-derived, "
        "no wall-clock time enters any number).",
        (
            f"Working tree: dirty at run start (n={meta['dirty_paths_n']} "
            "changed paths); the commit recorded above is the parent of "
            "uncommitted work."
            if meta["dirty_tree"]
            else "Working tree: clean at run start."
        ),
        f"Rule under test: db id={rule['db_id']} version={rule['version']} "
        f"status={rule['status']} native_rule_id={rule['native_rule_id']} "
        f"sigma id `{rule['sigma_rule_id']}` ({rule['title']}).",
        "Verdict codes: "
        + (", ".join(f"`{code}`" for code in meta["codes"]) or "none"),
        "",
        "## 1. Anti-leak checks",
        "",
        "| check | result | detail |",
        "|---|---|---|",
    ]
    for row in payload["anti_leak"]:
        lines.append(f"| `{row['check']}` | {row['result']} | {row['detail']} |")
    lines += [
        "",
        "## 2. Positive run (rule present)",
        "",
        f"Export `{pos['dir']}`: n={pos['n_events']} events from "
        f"n={pos['n_archive_files']} archive file(s), n={pos['n_alerts']} "
        f"alerts from n={pos['n_alert_files']} alert file(s); data window "
        f"{pos['data_window']}. Learned alerts n={pos['learned_n']}, "
        f"other-learned n={pos['other_learned_n']}, shipped "
        f"n={pos['shipped_n']}.",
        "",
        "| step | technique | window | expected | learned n | "
        "first delay | rule id/version | shipped | verdict |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in pos["steps"]:
        shipped = ", ".join(f"{rid}x{n}" for rid, n in row["shipped"].items()) or "-"
        lines.append(
            f"| {row['step']} | {row['technique']} | {row['window']} | "
            f"{row['expected']} | {row['learned_n']} | "
            f"{_fmt_delay(row['first_delay_s'])} | "
            f"{row['rule_db_id']}/v{row['rule_version']} | {shipped} | "
            f"{row['verdict']} |"
        )
    if pos["false_positives"]:
        lines += [
            "",
            f"Learned alerts outside every step window (false positives, "
            f"n={len(pos['false_positives'])} over n={pos['n_events']} "
            "events scanned):",
            "",
        ]
        for item in pos["false_positives"]:
            lines.append(f"- {item['time']} rule {item['rule_id']}")
    else:
        lines += [
            "",
            f"No learned alerts outside any step window (n=0 false "
            f"positives over n={pos['n_events']} events scanned).",
        ]
    lines += [
        "",
        "### Baseline backtest (same rule, same engine, 0 expected)",
        "",
        f"Baseline `{base['dir']}` ({base['mode']}): n={base['n_events']} "
        f"events, window {base['window']}, matches n={base['matches_n']}"
        + (f" ({', '.join(base['match_uids'][:10])})" if base["matches_n"] else "")
        + ".",
    ]
    if base["unloadable"]:
        lines.append(f"Rule unloadable at gate time: {base['unloadable']}.")
    lines += [
        "",
        "## 3. Negative control (rule absent)",
        "",
        f"Export `{neg['dir']}`: n={neg['n_events']} events, "
        f"n={neg['n_alerts']} alerts; data window {neg['data_window']}. "
        f"Learned-rule alerts n={neg['learned_n']} (must be 0), "
        f"other-learned n={neg['other_learned_n']}, shipped "
        f"n={neg['shipped_n']}.",
        "",
        "| step | technique | window | learned n | shipped |",
        "|---|---|---|---|---|",
    ]
    for row in neg["steps"]:
        shipped = ", ".join(f"{rid}x{n}" for rid, n in row["shipped"].items()) or "-"
        lines.append(
            f"| {row['step']} | {row['technique']} | {row['window']} | "
            f"{row['learned_n']} | {shipped} |"
        )
    lines += [
        "",
        "## 4. Ledger (model spend around detection)",
        "",
        f"Detection window: {ledger['detection_window']['start']} to "
        f"{ledger['detection_window']['end']} (first variant step to last "
        "learned-rule finding, both data-derived; rows on the boundary "
        "count as inside).",
        "",
    ]
    for segment in ("before", "inside", "after"):
        part = ledger["segments"][segment]
        attempts = part["attempts"]
        detail = (
            ", ".join(
                f"{entry['purpose']}/{entry['model']}x{entry['rows']}"
                for entry in attempts["by_purpose_model"]
            )
            or "no rows"
        )
        lines.append(
            f"- {segment}: llm_attempts n={attempts['rows']} ({detail}), "
            f"spend n={part['spend_rows']} (${part['spend_usd']:.6f})."
        )
    lines += [
        "The `inside` segment must be zero for detection (triage and "
        "analysis may run later and appear under `after`, reported here, "
        "never hidden).",
        "",
        "## 5. Honest limits (generated from the data above)",
        "",
        f"- Expected miss and missed (the rule's confirmed limit): "
        f"steps {limits['expected_miss_missed'] or 'none'}.",
        f"- Expected detect but missed (failures): "
        f"steps {limits['expected_detect_missed'] or 'none'}.",
        f"- Steps no rule of any kind covered (neither learned nor "
        f"shipped alerts in-window): "
        f"{limits['uncovered_by_any_rule'] or 'none'}.",
        f"- Distinct learned rules involved in the positive export: "
        f"n={limits['distinct_learned_rules']['n']} "
        f"(mine `{limits['distinct_learned_rules']['mine_sigma_id']}`, "
        f"others {limits['distinct_learned_rules']['other_ids'] or 'none'}).",
        f"- Training set: n={limits['training_set']['incidents_n']} "
        f"incident(s) (id {limits['training_set']['incident_id']}), "
        f"n={limits['training_set']['incident_events_n']} incident events, "
        f"n={limits['training_set']['cited_events_n']} cited events."
        + (
            f" {limits['training_set']['incident_events_note']}."
            if limits["training_set"]["incident_events_note"]
            else ""
        ),
        f"- Variant vs training behavior: "
        f"{'identical' if limits['behavior_same_as_training'] else 'DIFFERENT'} "
        f"technique sequence (train {limits['train_techniques']}, positive "
        f"{limits['positive_techniques']}, negative "
        f"{limits['negative_techniques']}); variant-declared distinct "
        f"values n={limits['variant_specific_declared_n']} "
        f"({', '.join(limits['variant_specific_declared']) or 'none declared'}).",
        f"- {limits['no_model_weight_updates']}",
        "",
        "## 6. Inputs",
        "",
        f"- train ground truth: `{payload['inputs']['train_gt']}` "
        f"(train steps n={len(limits['train_techniques'])}).",
        f"- positive export: `{payload['inputs']['positive']}` with "
        f"`{payload['inputs']['positive_gt']}`.",
        f"- negative export: `{payload['inputs']['negative']}` with "
        f"`{payload['inputs']['negative_gt']}`.",
        f"- baseline: `{base['dir']}`.",
    ]
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    """Build the gate2 argument parser."""
    parser = argparse.ArgumentParser(
        prog="corvus eval gate2",
        description="Gate-2 learning evidence for one stored rule.",
    )
    parser.add_argument("--rule", type=int, required=True, help="Stored rule id.")
    parser.add_argument("--train-gt", required=True, help="Training ground truth.")
    parser.add_argument("--positive", required=True, help="Variant export, rule on.")
    parser.add_argument("--positive-gt", required=True, help="Variant ground truth.")
    parser.add_argument("--negative", required=True, help="Variant export, rule off.")
    parser.add_argument("--negative-gt", required=True, help="Variant ground truth.")
    parser.add_argument(
        "--baseline-dir",
        default="data/replay-linux-baseline",
        help="Baseline store or export (default: %(default)s).",
    )
    parser.add_argument(
        "--train-dir",
        default="data/replay-linux-chain1",
        help="Training replay store holding the cited events (default: %(default)s).",
    )
    parser.add_argument(
        "--out",
        default="eval/reports/gate2.md",
        help="Markdown report path (default: %(default)s).",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``corvus eval gate2`` (0 VALID, 1 INVALID, 2 input)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.database_url:
        parser.error("DATABASE_URL is not set (or pass --database-url).")
    command = (
        f"corvus eval gate2 --rule {args.rule} --train-gt {args.train_gt} "
        f"--positive {args.positive} --positive-gt {args.positive_gt} "
        f"--negative {args.negative} --negative-gt {args.negative_gt} "
        f"--baseline-dir {args.baseline_dir} --train-dir {args.train_dir} "
        f"--out {args.out}"
    )
    dirty, dirty_n = git_dirty()
    try:
        result = run_gate2(
            database_url=args.database_url,
            rule_id=args.rule,
            train_gt=args.train_gt,
            positive=args.positive,
            positive_gt=args.positive_gt,
            negative=args.negative,
            negative_gt=args.negative_gt,
            baseline_dir=args.baseline_dir,
            train_dir=args.train_dir,
            producing_command=command,
            commit=git_commit(),
            dirty_tree=dirty,
            dirty_paths_n=dirty_n,
        )
    except GateInputError as exc:
        parser.error(str(exc))
        return 2
    out_md = Path(args.out)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(result), encoding="utf-8")
    out_json = out_md.with_suffix(".json")
    out_json.write_text(
        json.dumps(result.payload, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    print(f"gate2 verdict: {result.verdict}")
    if result.codes:
        print(f"codes: {', '.join(result.codes)}")
    print(f"report: {out_md} (+ {out_json.name})")
    return 0 if result.passed else 1
