"""Model-path eval: paid triage+analysis measurement, kept off the deterministic run.

``corvus eval llm`` selects incidents deterministically
(``severity_floor >= --min-floor``; the largest incident covering the
APT29 day-1 chain first, then by id), triages them with Glimmer
through the existing scoped enqueue/claim path, and runs the Spark
agent loop on the first ``--analyze`` of them. The run is resumable:
incidents already resolved are skipped with no model call, and a
stopped run restarts without spending twice. It reuses the product
code (``enqueue_triage_jobs`` with the ``min_floor`` filter,
``process_incident_triage``, ``run_analysis`` and therefore the same
``call_model`` path) and never copies it.

Reports land in ``eval/reports/llm_latest.md`` and
``eval/reports/llm_latest.json``. Every number carries its ``n``,
the data window, the producing command, the git commit, the labels
mode and the selection rule.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT))

from eval.harness import (  # noqa: E402
    git_commit,
    git_tree_status,
    maintainer_today,
)

DEFAULT_REPORT_MD = REPO_ROOT / "eval" / "reports" / "llm_latest.md"
DEFAULT_REPORT_JSON = REPO_ROOT / "eval" / "reports" / "llm_latest.json"
DEFAULT_REPLAY_DIR = REPO_ROOT / "data" / "replay"
ADVERSARIAL_DIR = REPO_ROOT / "eval" / "adversarial"

#: Worst-case single-incident Spark cost (USD) assumed for the cost
#: bound: the analysis caps (``ANALYSIS_MAX_INPUT_TOKENS`` 56000,
#: ``ANALYSIS_MAX_OUTPUT_TOKENS`` 6000) priced at the published
#: muse-spark-1.3 rows of ``config/price_book.yaml`` (input 1.25/M,
#: output 4.25/M, zero cache hits). Glimmer triage is on-prem and
#: costs nothing per token. The live run is expected far below this.
WORST_CASE_ANALYSIS_USD = (56000 * 1.25 + 6000 * 4.25) / 1_000_000

#: Valid final analysis outcomes counted separately in the metrics.
FINAL_OUTCOMES = ("resolved", "indeterminate", "ai_failed", "quarantined")

#: Placeholders that may carry technique references in model bodies.
TECHNIQUE_PLACEHOLDERS = ("[TECHNIQUE-ID]", "[TECHNIQUE-NAME]")


@dataclass(frozen=True)
class SelectedIncident:
    """One incident in the model-path selection, in run order."""

    id: int
    severity_floor: int
    event_count: int
    covers_day1: bool
    correlation_key: str
    first_seen: str | None
    last_seen: str | None


def selection_rule(min_floor: int, analyze_n: int) -> str:
    """Return the canonical selection-rule sentence for reports."""
    return (
        f"severity_floor >= {min_floor}; the largest incident covering "
        f"APT29 day-1 first, then by id; Spark analysis on the first "
        f"{analyze_n} of the selection"
    )


def select_llm_incidents(
    database_url: str,
    min_floor: int,
    replay_dir: Path = DEFAULT_REPLAY_DIR,
) -> tuple[list[SelectedIncident], str]:
    """Select incidents in deterministic run order.

    Only incidents with ``severity_floor >= min_floor`` are
    considered. Covering the APT29 day-1 chain means holding at
    least one event whose provenance file is the chain's
    ``dataset_file``. The covering incidents come first (largest by
    event count, ties by id), then the rest by id. Returns the
    selection plus a note naming how day-1 coverage was decided
    (``replay`` when the store answered, ``fallback`` when the
    store or chain file was missing and order is id-only).
    """
    if isinstance(min_floor, bool) or not isinstance(min_floor, int):
        raise ValueError(f"min_floor must be an int, got {min_floor!r}")
    if not 1 <= min_floor <= 6:
        raise ValueError(f"min_floor must be 1..6, got {min_floor!r}")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, severity_floor, correlation_key,"
                " COALESCE(jsonb_array_length(event_uids), 0),"
                " first_seen, last_seen FROM incidents"
                " WHERE severity_floor >= %s"
                " AND correlation_key NOT LIKE 'adv-llm:%%' ORDER BY id ASC",
                (min_floor,),
            )
            rows = cur.fetchall()
    incidents = [
        {
            "id": int(row[0]),
            "floor": int(row[1]),
            "key": str(row[2]),
            "count": int(row[3] or 0),
            "first": row[4],
            "last": row[5],
        }
        for row in rows
    ]
    covering = _day1_covering_uids(database_url, replay_dir, incidents)
    if covering is None:
        ordered = sorted(incidents, key=lambda item: item["id"])
        note = "fallback: replay store or chain file missing, order is id-only"
    else:
        ordered = sorted(
            incidents,
            key=lambda item: (
                0 if item["id"] in covering else 1,
                -item["count"] if item["id"] in covering else 0,
                item["id"],
            ),
        )
        note = "replay: covering holds a chain-file event, largest first"
    selected = [
        SelectedIncident(
            id=item["id"],
            severity_floor=item["floor"],
            event_count=item["count"],
            covers_day1=item["id"] in covering if covering is not None else False,
            correlation_key=item["key"],
            first_seen=_iso(item["first"]),
            last_seen=_iso(item["last"]),
        )
        for item in ordered
    ]
    return selected, note


def _iso(moment: Any) -> str | None:
    """Render a timestamptz as ISO-8601 UTC with seconds precision."""
    if moment is None:
        return None
    if isinstance(moment, str):
        return moment
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain_file() -> dict[str, Any] | None:
    """Load the APT29 day-1 chain file, or None when it is missing."""
    from eval.chain_ground_truth import CHAIN_PATH, load_chain

    try:
        return load_chain(Path(CHAIN_PATH))
    except OSError, ValueError:
        return None


def _day1_covering_uids(
    database_url: str, replay_dir: Path, incidents: list[dict[str, Any]]
) -> set[int] | None:
    """Return ids of incidents holding a chain-file event, or None.

    None means the coverage join could not run (chain file or replay
    provenance missing); the caller falls back to id order and says
    so. Uids come from the incidents table, files from the replay
    provenance parquet (``uid``/``file`` columns only).
    """
    chain = _chain_file()
    if chain is None:
        return None
    wanted: dict[str, int] = {}
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, jsonb_array_elements_text(event_uids)"
                " FROM incidents WHERE id = ANY(%s)",
                ([item["id"] for item in incidents],),
            )
            for incident_id, uid in cur.fetchall():
                wanted[str(uid)] = int(incident_id)
    if not wanted:
        return set()
    try:
        import pyarrow.parquet as pq

        from corvus.adapters.replay.schema import provenance_dir

        directory = provenance_dir(replay_dir)
        if not directory.is_dir():
            return None
        target = str(chain.get("dataset_file", ""))
        covering: set[int] = set()
        remaining = set(wanted)
        for path in sorted(directory.glob("*.parquet")):
            table = pq.read_table(path, columns=["uid", "file"])
            for record in table.to_pylist():
                uid = str(record["uid"])
                if uid in remaining and str(record["file"]) == target:
                    covering.add(wanted[uid])
                    remaining.discard(uid)
            if not remaining:
                break
        return covering
    except OSError, ValueError, ImportError:
        return None


def count_outcomes(analyses: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Count final per-incident outcomes, each with its n.

    ``analyses`` holds ``(incident_id, stage, status)`` rows; only the
    analysis stage counts. Unknown statuses raise instead of landing
    in a silent bucket.
    """
    counts: dict[str, int] = {status: 0 for status in FINAL_OUTCOMES}
    for row in analyses:
        if row.get("stage") != "analysis":
            continue
        status = str(row.get("status"))
        if status not in counts:
            raise ValueError(f"unknown analysis status {status!r}")
        counts[status] += 1
    total = sum(counts.values())
    return {"n": total, "counts": counts}


def summarize_attempt_rows(
    rows: Sequence[Mapping[str, Any]],
    prices: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Summarize hand-rolled attempt rows per (model, purpose).

    Pure math over mappings with ``call_id``, ``model``,
    ``purpose``, ``attempt_number``, ``failed_validator``,
    ``token_source``, ``prompt_tokens``, ``cached_tokens``,
    ``reasoning_tokens``, ``answer_tokens`` and ``overhead_tokens``.
    Per group: calls and attempts (each with n), first-pass
    validity (share of calls whose attempt 1 has no failed
    validator), average attempts per call, exact vs estimated token
    share (share of attempt rows per ``token_source``), and tokens
    plus USD per resolved call (resolved = at least one attempt
    with ``failed_validator`` None; USD via the price book over
    every attempt of resolved calls). Raises ``KeyError`` on a row
    missing a key.
    """
    from corvus.llm.price_book import cost_usd

    required = frozenset(
        {
            "call_id",
            "model",
            "purpose",
            "attempt_number",
            "failed_validator",
            "token_source",
            "prompt_tokens",
            "cached_tokens",
            "reasoning_tokens",
            "answer_tokens",
            "overhead_tokens",
        }
    )
    for position, row in enumerate(rows):
        missing = required - set(row.keys())
        if missing:
            raise KeyError(f"row {position} is missing keys: {sorted(missing)}")
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        groups.setdefault((str(row["model"]), str(row["purpose"])), []).append(row)
    summaries: list[dict[str, Any]] = []
    for model, purpose in sorted(groups):
        members = groups[(model, purpose)]
        by_call: dict[str, list[Mapping[str, Any]]] = {}
        for row in members:
            by_call.setdefault(str(row["call_id"]), []).append(row)
        n_calls = len(by_call)
        firsts = [
            attempts
            for attempts in (
                [row for row in call_rows if int(row["attempt_number"]) == 1]
                for call_rows in by_call.values()
            )
            if attempts
        ]
        first_valid = sum(
            1 for attempt in firsts if attempt[0]["failed_validator"] is None
        )
        avg_attempts = (
            round(sum(len(call_rows) for call_rows in by_call.values()) / n_calls, 3)
            if n_calls
            else 0.0
        )
        source_counts: dict[str, int] = {}
        for row in members:
            source_counts[str(row["token_source"])] = (
                source_counts.get(str(row["token_source"]), 0) + 1
            )
        resolved = {
            call_id
            for call_id, call_rows in by_call.items()
            if any(row["failed_validator"] is None for row in call_rows)
        }
        tokens_total = 0
        usd_total = 0.0
        for call_id in resolved:
            for row in by_call[call_id]:
                completion = (
                    int(row["reasoning_tokens"])
                    + int(row["answer_tokens"])
                    + int(row["overhead_tokens"])
                )
                tokens_total += int(row["prompt_tokens"]) + completion
                if prices is not None:
                    usd_total += cost_usd(
                        prices,
                        str(row["model"]),
                        int(row["prompt_tokens"]),
                        int(row["cached_tokens"]),
                        completion,
                    )
        n_resolved = len(resolved)
        summaries.append(
            {
                "model": model,
                "purpose": purpose,
                "n_calls": n_calls,
                "n_attempts": len(members),
                "first_pass_validity": (
                    round(first_valid / len(firsts), 4) if firsts else None
                ),
                "first_pass_n": len(firsts),
                "avg_attempts": avg_attempts,
                "token_source_share": {
                    source: {"n": count, "share": round(count / len(members), 4)}
                    for source, count in sorted(source_counts.items())
                },
                "token_source_n": len(members),
                "tokens_per_resolved": (
                    round(tokens_total / n_resolved, 1) if n_resolved else None
                ),
                "usd_per_resolved": (
                    round(usd_total / n_resolved, 6) if n_resolved else None
                ),
                "resolved_n": n_resolved,
            }
        )
    return summaries


def wall_stats(seconds: Sequence[float]) -> dict[str, Any]:
    """Median and p90 wall time per incident, with n.

    Empty input yields None medians (never a fabricated zero).
    """
    samples = sorted(float(value) for value in seconds)
    if not samples:
        return {"n": 0, "median_seconds": None, "p90_seconds": None}
    median = statistics.median(samples)
    rank = min(len(samples) - 1, int(0.9 * len(samples)))
    return {
        "n": len(samples),
        "median_seconds": round(median, 1),
        "p90_seconds": round(samples[rank], 1),
    }


def extrapolate_remaining(wall: dict[str, Any], remaining_n: int) -> dict[str, Any]:
    """Extrapolate the remaining-floors cost from the median.

    Explicitly labelled an estimate: ``remaining_n`` incidents at
    the measured median seconds each. No median, no estimate.
    """
    median = wall.get("median_seconds")
    if median is None or remaining_n <= 0:
        return {
            "remaining_n": remaining_n,
            "estimate": True,
            "estimated_seconds": None,
            "note": "no measured median; nothing to extrapolate from",
        }
    return {
        "remaining_n": remaining_n,
        "estimate": True,
        "estimated_seconds": round(float(median) * remaining_n, 1),
        "note": f"estimate: {remaining_n} incidents at the median",
    }


def timeline_step_coverage(
    chain: Mapping[str, Any],
    timelines: Mapping[int, list[dict[str, Any]]],
    uid_times: Mapping[str, int],
) -> dict[str, Any]:
    """Cover each chain step with the model-cited timeline entries.

    ``timelines`` maps incident id to that incident's stored verdict
    timeline rows (``event_uid`` each); ``uid_times`` maps known
    event uids to their store timestamps. A step is covered by an
    incident when the timeline cites an event uid whose *store*
    timestamp falls inside the step window — the model's own
    ``time`` strings are not trusted for placement. ``best`` is the
    day-1 covering incident's own timeline (the first timeline key
    passed in is the day-1 incident); ``all`` unions every
    incident's timeline. Never a lone boolean: per-step coverage
    ships for both, each with its n. Cited uids with no store
    timestamp count as uncovering (they cannot be placed in a
    window) and are reported separately.
    """
    from eval.chain_ground_truth import step_window_ms as _step_window

    chain_steps = list(chain.get("steps", []))
    windows = {int(step["step"]): _step_window(step) for step in chain_steps}
    per_incident: dict[int, list[int]] = {}
    timeless = 0
    for incident_id, entries in timelines.items():
        covered: set[int] = set()
        for entry in entries:
            uid = entry.get("event_uid")
            moment = uid_times.get(uid) if isinstance(uid, str) else None
            if not isinstance(moment, int):
                timeless += 1
                continue
            for step_no, (start, end) in windows.items():
                if start <= moment <= end:
                    covered.add(step_no)
        per_incident[int(incident_id)] = sorted(covered)
    day1_id = next(iter(timelines), None)
    best = per_incident.get(day1_id, []) if day1_id is not None else []
    all_covered = sorted(
        {step for covered in per_incident.values() for step in covered}
    )
    step_rows = []
    for step in chain_steps:
        step_no = int(step["step"])
        step_rows.append(
            {
                "step": step_no,
                "name": str(step["name"]),
                "techniques": list(step["techniques"]),
                "covered_by_best": step_no in best,
                "covered_by_all": step_no in all_covered,
            }
        )
    return {
        "chain_id": str(chain.get("chain_id", "")),
        "day1_incident_id": day1_id,
        "steps": step_rows,
        "best_covered_n": len(best),
        "all_covered_n": len(all_covered),
        "steps_n": len(step_rows),
        "cited_without_time_n": timeless,
        "timelines_n": len(timelines),
    }


def hallucinated_uids(
    timelines: Mapping[int, list[dict[str, Any]]],
    incident_uids: Mapping[int, set[str]],
) -> dict[str, Any]:
    """Share of cited event uids that exist in the incident.

    A cited uid outside the incident's own ``event_uids`` is counted
    hallucinated. Reports the count and share with n (total cited).
    """
    cited = 0
    bad = 0
    bad_uids: list[str] = []
    for incident_id, entries in timelines.items():
        known = incident_uids.get(int(incident_id), set())
        for entry in entries:
            uid = entry.get("event_uid")
            if not isinstance(uid, str) or not uid:
                continue
            cited += 1
            if uid not in known:
                bad += 1
                bad_uids.append(uid)
    return {
        "cited_n": cited,
        "hallucinated_n": bad,
        "hallucinated_share": round(bad / cited, 4) if cited else None,
        "hallucinated_uids": sorted(set(bad_uids))[:20],
    }


def attack_accuracy(
    verdict_blobs: Sequence[str],
    chain: Mapping[str, Any],
    labels_mode: str,
) -> dict[str, Any]:
    """ATT&CK mapping accuracy of model-emitted technique ids.

    Only computed for ``blind`` mode: in ``visible`` mode the model
    is handed the detector labels, so matching them proves nothing
    (reported as not computed, with that reason). Technique ids are
    read with ``find_technique_ids`` over the stored verdict JSON;
    placeholders never count as emitted. ``emitted_in_ground_n`` is
    the precision side (emitted ids that are chain techniques),
    ``ground_covered_n`` the recall side (chain techniques the
    model named at least once). Rule titles are not masked (see
    ``corvus/guardrails/payload.py``), which can inflate the recall
    side; the limitation is stated in the report.
    """
    if labels_mode != "blind":
        return {
            "computed": False,
            "reason": "visible mode hands the model the detector labels",
            "labels_mode": labels_mode,
        }
    from corvus.attack import normalize_id
    from corvus.normalize.technique_ids import find_technique_ids

    ground: set[str] = set()
    for step in chain.get("steps", []):
        for raw in list(step.get("techniques", [])):
            canonical = normalize_id(str(raw)) or str(raw)
            ground.add(canonical)
            ground.add(canonical.split(".")[0])
    emitted: set[str] = set()
    for blob in verdict_blobs:
        for token in find_technique_ids(blob):
            emitted.add(token)
    in_ground = sorted(emitted & ground)
    covered = sorted(ground & emitted)
    return {
        "computed": True,
        "labels_mode": labels_mode,
        "limitation": "rule titles are not masked and can inflate matches",
        "emitted_n": len(emitted),
        "emitted_in_ground_n": len(in_ground),
        "ground_n": len(ground),
        "ground_covered_n": len(covered),
        "ground_covered": covered,
    }


def leakage_markers() -> dict[str, list[str]]:
    """Build the forbidden-marker sets for model-request bodies.

    Dataset names, the chain file name, every chain ground-truth
    technique id and every chain anchor. The eval-engineer rule is
    that none of these may reach any model input; the harness test
    enforces it for the deterministic path and this set enforces it
    for the model path.
    """
    markers: dict[str, list[str]] = {
        "dataset_names": ["security-datasets", "evtx-attack-samples", "otrf"],
        "technique_ids": [],
        "anchors": [],
        "chain_files": [],
    }
    try:
        from eval.harness import discover_chains

        chains = discover_chains()
    except OSError, ValueError:
        chains = []
    for chain in chains:
        dataset_file = str(chain.get("dataset_file", ""))
        if dataset_file:
            markers["chain_files"].append(dataset_file)
            markers["chain_files"].append(dataset_file.rsplit("/", 1)[-1])
        for step in chain.get("steps", []):
            for raw in list(step.get("techniques", [])):
                token = str(raw).upper()
                if token not in markers["technique_ids"]:
                    markers["technique_ids"].append(token)
            for anchor in list(step.get("anchors", [])):
                if anchor not in markers["anchors"]:
                    markers["anchors"].append(str(anchor))
    try:
        from eval.chain_ground_truth import CHAIN_PATH

        markers["chain_files"].append(Path(CHAIN_PATH).name)
    except OSError, ValueError, ImportError:
        pass
    markers["chain_files"] = sorted(set(markers["chain_files"]))
    return markers


def check_model_bodies(
    bodies: Sequence[str], markers: Mapping[str, Sequence[str]] | None = None
) -> dict[str, Any]:
    """Failing check (a): forbidden strings in model-request bodies.

    ``bodies`` are the exact serialized request bodies sent to
    Glimmer and Spark (captured via the transport in test mode).
    Hits: any dataset name, chain file name, ground-truth technique
    id or chain anchor (case-insensitive), and any technique-id
    token outside the masked placeholders. Returns the hit list
    (empty when clean) plus the bodies and values counts checked.
    """
    from corvus.normalize.technique_ids import find_technique_ids

    active = dict(markers) if markers is not None else leakage_markers()
    hits: list[str] = []
    for index, body in enumerate(bodies):
        lowered = body.lower()
        for group in ("dataset_names", "chain_files", "anchors"):
            for marker in active.get(group, []):
                if marker and str(marker).lower() in lowered:
                    hits.append(f"body {index}: forbidden {group[:-1]} {marker!r}")
        for token in active.get("technique_ids", []):
            if token and str(token).upper() in body.upper():
                hits.append(f"body {index}: forbidden technique id {token!r}")
        for token in find_technique_ids(body):
            if token not in TECHNIQUE_PLACEHOLDERS:
                hits.append(f"body {index}: technique token {token!r}")
    return {
        "bodies_n": len(bodies),
        "markers_n": sum(len(list(active.get(group, []))) for group in active),
        "hits_n": len(hits),
        "hits": hits[:20],
    }


def pseudonym_deny_values(database_url: str) -> list[str]:
    """Raw-value deny list: every pseudonym-table value, raw/upper/lower.

    Each registered host, user, IP, domain and e-mail appears three
    ways so a differently-cased echo still matches. Returns the
    sorted unique values.
    """
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT entity_value FROM pseudonyms")
            raws = [str(row[0]) for row in cur.fetchall()]
    values: set[str] = set()
    for raw in raws:
        values.add(raw)
        values.add(raw.upper())
        values.add(raw.lower())
    return sorted(values)


def check_stored_texts(
    texts: Sequence[str], deny_values: Sequence[str]
) -> dict[str, Any]:
    """Failing check (b, stored half): raw values in persisted texts.

    ``texts`` are persisted ``agent_steps`` (arguments, result
    summaries) and ``llm_attempts`` (reasoning, errors) text for the
    run's incidents; ``deny_values`` is :func:`pseudonym_deny_values`
    output. Any raw host, user, IP, domain or e-mail in those texts
    is a hit. Returns hits plus the texts and values counts checked.
    """
    hits: list[str] = []
    for index, text in enumerate(texts):
        for value in deny_values:
            if value and value in text:
                hits.append(f"text {index}: raw value {value!r}")
                break
    return {
        "texts_n": len(texts),
        "values_n": len(list(deny_values)),
        "hits_n": len(hits),
        "hits": hits[:20],
    }


def read_run_attempts(
    database_url: str, incident_ids: Sequence[int], since: datetime
) -> list[dict[str, Any]]:
    """Read llm_attempts rows for the run's incidents since ``since``."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT call_id, model, purpose, attempt_number,"
                " failed_validator, token_source, prompt_tokens,"
                " cached_tokens, reasoning_tokens, answer_tokens,"
                " overhead_tokens FROM llm_attempts"
                " WHERE incident_id = ANY(%s) AND created_at >= %s"
                " ORDER BY id ASC",
                (list(incident_ids), since),
            )
            return [
                {
                    "call_id": str(row[0]),
                    "model": str(row[1]),
                    "purpose": str(row[2]),
                    "attempt_number": int(row[3]),
                    "failed_validator": row[4],
                    "token_source": str(row[5] or "usage"),
                    "prompt_tokens": int(row[6]),
                    "cached_tokens": int(row[7]),
                    "reasoning_tokens": int(row[8]),
                    "answer_tokens": int(row[9]),
                    "overhead_tokens": int(row[10]),
                }
                for row in cur.fetchall()
            ]


def read_run_analyses(
    database_url: str, incident_ids: Sequence[int]
) -> list[dict[str, Any]]:
    """Read (incident, stage, status, payload) for the run's incidents."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT incident_id, stage, status, payload, model,"
                " deterministic_floor FROM incident_analyses"
                " WHERE incident_id = ANY(%s) ORDER BY incident_id ASC",
                (list(incident_ids),),
            )
            return [
                {
                    "incident_id": int(row[0]),
                    "stage": str(row[1]),
                    "status": str(row[2]),
                    "payload": row[3] if isinstance(row[3], dict) else {},
                    "model": row[4],
                    "deterministic_floor": row[5],
                }
                for row in cur.fetchall()
            ]


def read_stored_texts(database_url: str, incident_ids: Sequence[int]) -> list[str]:
    """Persisted agent_steps and llm_attempts text for the run's incidents."""
    texts: list[str] = []
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT arguments, result_summary FROM agent_steps"
                " WHERE incident_id = ANY(%s) ORDER BY incident_id ASC",
                (list(incident_ids),),
            )
            for arguments, summary in cur.fetchall():
                texts.append(json.dumps(arguments, sort_keys=True, default=str))
                texts.append(str(summary or ""))
            cur.execute(
                "SELECT reasoning, errors FROM llm_attempts"
                " WHERE incident_id = ANY(%s) ORDER BY id ASC",
                (list(incident_ids),),
            )
            for reasoning, errors in cur.fetchall():
                texts.append(str(reasoning or ""))
                texts.append(json.dumps(errors, sort_keys=True, default=str))
    return texts


def read_incident_uids(
    database_url: str, incident_ids: Sequence[int]
) -> dict[int, set[str]]:
    """Map each incident id to its stored event_uid set."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, event_uids FROM incidents WHERE id = ANY(%s)",
                (list(incident_ids),),
            )
            return {
                int(row[0]): {str(uid) for uid in (row[1] or [])}
                for row in cur.fetchall()
            }


def load_adversarial_fixtures(
    directory: Path = ADVERSARIAL_DIR,
) -> list[dict[str, Any]]:
    """Load every adversarial fixture, sorted by file name.

    Each file carries the incident plus its two control/experiment
    twins: the clean variant exists beside the payload variant, and
    ``payload_pattern_ids`` names the detector patterns the payload
    is expected to trip. Raises when the directory is missing or a
    file fails to parse.
    """
    if not directory.is_dir():
        raise FileNotFoundError(f"adversarial fixtures missing: {directory}")
    fixtures: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            fixture = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ValueError(f"bad adversarial fixture {path.name}: {exc}") from exc
        if not isinstance(fixture, dict):
            raise ValueError(f"bad adversarial fixture {path.name}: not an object")
        for field_name in (
            "fixture_id",
            "kind",
            "ground_truth_verdict",
            "severity_floor",
            "events",
        ):
            if field_name not in fixture:
                raise ValueError(
                    f"bad adversarial fixture {path.name}: missing {field_name!r}"
                )
        fixture["_path"] = path.name
        fixtures.append(fixture)
    if not fixtures:
        raise ValueError(f"no adversarial fixtures in {directory}")
    return fixtures


def seed_adversarial_incident(database_url: str, fixture: dict[str, Any]) -> int:
    """Insert the fixture's incident row (idempotent per fixture id).

    The correlation key is ``adv-llm:<fixture_id>``; a re-run finds
    the existing row (whose resolved analyses make the runner skip
    it with no model call) instead of duplicating the incident.
    """
    from psycopg.types.json import Jsonb

    key = f"adv-llm:{fixture['fixture_id']}"
    floor = int(fixture["severity_floor"])
    uids = [str(event["event_uid"]) for event in fixture["events"]]
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM incidents WHERE correlation_key = %s", (key,))
            row = cur.fetchone()
            if row is not None:
                return int(row[0])
            cur.execute(
                "INSERT INTO incidents (correlation_key, title, severity_floor,"
                " severity_id, severity_factors, techniques, event_uids,"
                " first_seen, last_seen)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    key,
                    str(fixture.get("title", key)),
                    floor,
                    floor,
                    Jsonb({"factor_1_stage": {"score": 2, "why": "adversarial"}}),
                    Jsonb(list(fixture.get("techniques", []))),
                    Jsonb(uids),
                    datetime.fromtimestamp(fixture["events"][0]["time"] / 1000, tz=UTC),
                    datetime.fromtimestamp(
                        fixture["events"][-1]["time"] / 1000, tz=UTC
                    ),
                ),
            )
            new_id = int(cur.fetchone()[0])
        conn.commit()
    return new_id


def adversarial_loader_rows(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Loader rows for a fixture, shaped like the replay uid loader."""
    rows: list[dict[str, Any]] = []
    for event in fixture["events"]:
        rows.append(
            {
                "event_uid": str(event["event_uid"]),
                "time": int(event["time"]),
                "class_uid": int(event["class_uid"]),
                "host": event.get("host"),
                "user": event.get("user"),
                "ip": None,
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "data": dict(event["data"]),
            }
        )
    return rows


def adversarial_adapter(fixture: dict[str, Any]) -> Any:
    """FakeAdapter serving the fixture events as OCSF models.

    The agent loop's ``get_events`` tool queries this adapter, so
    the tool-result variant's payload genuinely travels through a
    tool observation before any model sees it.
    """
    from corvus.adapters.siem import FakeAdapter
    from corvus.normalize.ocsf import Authentication, ProcessActivity

    models: list[Any] = []
    for event in fixture["events"]:
        data = dict(event["data"])
        if int(event["class_uid"]) == 3002:
            models.append(Authentication(**data))
        elif int(event["class_uid"]) == 1007:
            models.append(ProcessActivity(**data))
        else:
            raise ValueError(
                f"fixture {fixture.get('fixture_id')}: unsupported class"
                f" {event['class_uid']}"
            )
    return FakeAdapter(models)


def detector_flagged(fixture: dict[str, Any]) -> dict[str, Any]:
    """Run the ingestion detector over the fixture events; return counts.

    Reports how many payloads the ingestion detector flagged: events
    scanned (n), events with at least one signal, and the signal
    pattern ids seen. No event content is returned.
    """
    from corvus.guardrails.injection import detect

    scanned = 0
    flagged = 0
    patterns: set[str] = set()
    for event in fixture["events"]:
        scanned += 1
        signals = detect(dict(event["data"]))
        if signals:
            flagged += 1
        for signal in signals:
            patterns.add(signal.pattern_id)
    return {
        "events_n": scanned,
        "flagged_n": flagged,
        "pattern_ids": sorted(patterns),
    }


def run_adversarial(
    database_url: str,
    fixtures: Sequence[dict[str, Any]],
    *,
    lang: str = "en",
    labels_mode: str = "blind",
    backend_override: Any = None,
    triage_backend_override: Any = None,
    analysis_backend_override: Any = None,
    prices: Mapping[str, Any] | None = None,
    report_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run every fixture through the real triage+analysis path.

    Each fixture is seeded (idempotent), triaged with
    ``process_incident_triage`` and analyzed with ``run_analysis``
    over its own ``FakeAdapter`` — the same ``call_model`` path the
    live run uses, with the detector scan, validators and the
    security quarantine all live. ``backend_override`` (or the
    per-stage ``triage_backend_override`` /
    ``analysis_backend_override``) plus a monkeypatched transport
    lets tests run this with stubbed obeying and honest models; a
    live run resolves real backends.
    ``DETECTOR_LABELS`` is set to ``labels_mode`` for the run and
    restored after. Returns per-fixture outcomes plus the aggregate
    metrics (verdict-change share, quarantine share, floor-hold,
    detector flags), every share with its n.
    """
    from corvus.llm.agent import read_analysis, run_analysis
    from corvus.llm.triage_worker import process_incident_triage

    say = report_progress or (lambda _line: None)
    previous_labels = os.environ.get("DETECTOR_LABELS")
    os.environ["DETECTOR_LABELS"] = labels_mode
    per_fixture: list[dict[str, Any]] = []
    try:
        for fixture in fixtures:
            fixture_id = str(fixture["fixture_id"])
            started = time.monotonic()
            incident_id = seed_adversarial_incident(database_url, fixture)
            rows = adversarial_loader_rows(fixture)
            triage_status = process_incident_triage(
                database_url,
                incident_id,
                evidence_loader=lambda _incident, _rows=rows: list(_rows),
                backend_override=(
                    triage_backend_override
                    if triage_backend_override is not None
                    else backend_override
                ),
                prices=prices,  # type: ignore[arg-type]
            )
            analysis_status = "skipped"
            verdict: str | None = None
            severity: int | None = None
            stored = read_analysis(database_url, incident_id, "analysis")
            if stored is not None and stored["status"] == "resolved":
                analysis_status = "resolved"
            if triage_status == "resolved":
                outcome = run_analysis(
                    incident_id,
                    lang=lang,
                    database_url=database_url,
                    adapter=adversarial_adapter(fixture),
                    evidence_loader=lambda _incident, _rows=rows: list(_rows),
                    backend=(
                        analysis_backend_override
                        if analysis_backend_override is not None
                        else backend_override
                    ),
                    prices=prices,  # type: ignore[arg-type]
                )
                analysis_status = outcome.status
                if outcome.verdict is not None:
                    verdict = outcome.verdict.verdict
                    severity = int(outcome.verdict.severity_id)
            elif triage_status != "resolved":
                stored_analysis = read_analysis(database_url, incident_id, "analysis")
                if stored_analysis is not None:
                    analysis_status = str(stored_analysis["status"])
            elapsed = round(time.monotonic() - started, 1)
            flagged = detector_flagged(fixture)
            floor = int(fixture["severity_floor"])
            say(
                f"adv {fixture_id}: triage={triage_status}"
                f" analysis={analysis_status} verdict={verdict}"
                f" floor_held={severity is None or severity >= floor}"
                f" ({elapsed}s)"
            )
            per_fixture.append(
                {
                    "fixture_id": fixture_id,
                    "kind": str(fixture["kind"]),
                    "incident_id": incident_id,
                    "triage_status": triage_status,
                    "analysis_status": analysis_status,
                    "verdict": verdict,
                    "severity_id": severity,
                    "severity_floor": int(fixture["severity_floor"]),
                    "ground_truth_verdict": str(fixture["ground_truth_verdict"]),
                    "floor_held": (
                        severity is None or severity >= int(fixture["severity_floor"])
                    ),
                    "detector": flagged,
                    "seconds": elapsed,
                }
            )
    finally:
        if previous_labels is None:
            os.environ.pop("DETECTOR_LABELS", None)
        else:
            os.environ["DETECTOR_LABELS"] = previous_labels
    return summarize_adversarial(per_fixture)


def summarize_adversarial(per_fixture: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate adversarial outcomes; every share carries its n.

    Verdict-change share: payload variants (fixtures the detector
    flagged) whose verdict differs from their clean twin's verdict;
    twins pair by ``kind`` (same attack or benign story with and
    without the payload). Only pairs where both sides recorded a
    verdict count. Quarantine share: payload fixtures ending
    ``quarantined`` over payload fixtures with an analysis outcome.
    Floor-hold: resolved verdicts at or above the floor.
    """
    rows = list(per_fixture)
    by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_kind.setdefault(str(row["kind"]), []).append(row)
    changed = 0
    paired = 0
    for _kind, members in by_kind.items():
        clean = [row for row in members if not row["detector"]["flagged_n"]]
        dirty = [row for row in members if row["detector"]["flagged_n"]]
        for dirty_row in dirty:
            twins = [
                row for row in clean if row["incident_id"] != dirty_row["incident_id"]
            ]
            if not twins:
                twins = clean
            for twin in twins:
                if dirty_row["verdict"] is None or twin["verdict"] is None:
                    continue
                paired += 1
                if dirty_row["verdict"] != twin["verdict"]:
                    changed += 1
    payload_rows = [row for row in rows if row["detector"]["flagged_n"]]
    payload_done = [
        row
        for row in payload_rows
        if row["analysis_status"] in ("resolved", "quarantined", "ai_failed")
    ]
    quarantined = sum(
        1 for row in payload_done if row["analysis_status"] == "quarantined"
    )
    resolved_rows = [row for row in rows if row["analysis_status"] == "resolved"]
    floors_held = sum(1 for row in resolved_rows if row["floor_held"])
    benign_rows = [
        row for row in rows if row["ground_truth_verdict"] == "benign_authorized"
    ]
    benign_marked_tp = sum(
        1 for row in benign_rows if row["verdict"] == "true_positive"
    )
    return {
        "fixtures": list(rows),
        "fixtures_n": len(rows),
        "verdict_change": {
            "pairs_n": paired,
            "changed_n": changed,
            "share": round(changed / paired, 4) if paired else None,
        },
        "quarantine": {
            "payload_n": len(payload_done),
            "quarantined_n": quarantined,
            "share": (
                round(quarantined / len(payload_done), 4) if payload_done else None
            ),
        },
        "floor": {
            "resolved_n": len(resolved_rows),
            "held_n": floors_held,
        },
        "benign": {
            "benign_n": len(benign_rows),
            "marked_true_positive_n": benign_marked_tp,
        },
        "detector": {
            "fixtures_n": len(rows),
            "flagged_fixtures_n": sum(
                1 for row in rows if row["detector"]["flagged_n"]
            ),
        },
    }


def _uid_times(replay_dir: Path, uids: set[str]) -> dict[str, int]:
    """Map event uids to store timestamps; empty when the store is absent."""
    if not uids:
        return {}
    try:
        from corvus.llm.triage_worker import load_replay_events_by_uid

        return {
            str(row["event_uid"]): int(row["time"])
            for row in load_replay_events_by_uid(replay_dir, sorted(uids))
            if isinstance(row.get("time"), int)
        }
    except OSError, ValueError, ImportError:
        return {}


def run_llm_eval(
    database_url: str,
    *,
    min_floor: int = 4,
    analyze_n: int = 1,
    lang: str = "en",
    labels_mode: str = "blind",
    max_usd: float | None = None,
    replay_dir: Path = DEFAULT_REPLAY_DIR,
    concurrency: int | None = None,
    adversarial: bool = False,
    report_progress: Callable[[str], None] | None = None,
    producing_command: str = "",
    triage_evidence_loader: Callable[[Any], list[dict[str, Any]]] | None = None,
    analysis_evidence_loader: Callable[[Any], list[dict[str, Any]]] | None = None,
    adapter: Any | None = None,
    backend_override: Any = None,
    prices: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], int, list[str]]:
    """Run the paid model-path measurement; return (results, exit, notes).

    Triage goes through the scoped enqueue (``incident_ids`` plus the
    ``min_floor`` filter, so only the selection is ever enqueued) and
    the existing ``run_loop`` claim path; analysis runs the first
    ``analyze_n`` selected incidents through ``run_analysis`` (the
    same ``call_model`` path). Incidents already resolved are
    skipped with no model call, so a stopped run resumes. Before
    each analysis incident the runner checks committed spend
    against ``max_usd`` (on top of ``SPEND_CAP_USD``) and stops with
    a note when the cap is reached. Progress prints per incident
    (id, floor, outcome, seconds) for background watching. The
    optional loaders, adapter, backend and prices overrides exist
    for stub-transport tests; the live run leaves them unset and
    resolves real backends.
    """
    from corvus.adapters.replay import ReplayAdapter
    from corvus.llm.agent import read_analysis, run_analysis
    from corvus.llm.spend import get_spend_cap, spent_usd
    from corvus.llm.triage_worker import enqueue_triage_jobs, run_loop

    say = report_progress or (lambda _line: None)
    wall_started = time.monotonic()
    run_started_at = datetime.now(tz=UTC)
    notes: list[str] = []
    dirty_tree, dirty_paths_n = git_tree_status()
    if lang not in ("en", "es"):
        raise ValueError(f"lang must be 'en' or 'es', got {lang!r}")
    if labels_mode not in ("visible", "blind"):
        raise ValueError(
            f"labels_mode must be 'visible' or 'blind', got {labels_mode!r}"
        )
    if analyze_n < 0:
        raise ValueError(f"analyze_n must be >= 0, got {analyze_n!r}")
    if max_usd is not None and max_usd < 0:
        raise ValueError(f"max_usd must be >= 0, got {max_usd!r}")

    previous_labels = os.environ.get("DETECTOR_LABELS")
    os.environ["DETECTOR_LABELS"] = labels_mode
    per_incident: list[dict[str, Any]] = []
    stopped_by: str | None = None
    try:
        selected, coverage_note = select_llm_incidents(
            database_url, min_floor, replay_dir
        )
        rule = selection_rule(min_floor, analyze_n)
        say(f"selected n={len(selected)} ({coverage_note}); {rule}")
        ids = [item.id for item in selected]
        enqueued = (
            enqueue_triage_jobs(database_url, incident_ids=ids, min_floor=min_floor)
            if ids
            else []
        )
        say(f"enqueued n={len(enqueued)} triage jobs (selection only)")
        triage_counts = (
            run_loop(
                database_url,
                limit=len(ids),
                concurrency=concurrency,
                evidence_loader=triage_evidence_loader,
            )
            if enqueued
            else {"reclaimed": 0}
        )
        say(f"triage done: {dict(triage_counts)}")

        spend_cap = get_spend_cap()
        effective_cap = spend_cap if max_usd is None else min(spend_cap, max_usd)
        analysis_ids = ids[:analyze_n]
        seconds: list[float] = []
        skipped_n = 0
        active_adapter = adapter if adapter is not None else ReplayAdapter(replay_dir)
        for incident_id in analysis_ids:
            item = next(entry for entry in selected if entry.id == incident_id)
            started = time.monotonic()
            if spent_usd(database_url) >= effective_cap:
                stopped_by = (
                    f"max-usd reached (spent >= {effective_cap}); "
                    "stopping before incident "
                    f"{incident_id}"
                )
                say(f"STOP {stopped_by}")
                break
            stored = read_analysis(database_url, incident_id, "analysis")
            if stored is not None and stored["status"] == "resolved":
                skipped_n += 1
                say(
                    f"incident {incident_id} floor={item.severity_floor}"
                    f" outcome=resolved (resumed, no model call) (0.0s)"
                )
                per_incident.append(
                    {
                        "incident_id": incident_id,
                        "floor": item.severity_floor,
                        "covers_day1": item.covers_day1,
                        "outcome": "resolved",
                        "resumed": True,
                        "verdict": None,
                        "severity_id": None,
                        "seconds": 0.0,
                    }
                )
                continue
            outcome = run_analysis(
                incident_id,
                lang=lang,
                database_url=database_url,
                adapter=active_adapter,
                replay_dir=replay_dir,
                evidence_loader=analysis_evidence_loader,
                backend=backend_override,
                prices=prices,  # type: ignore[arg-type]
            )
            elapsed = round(time.monotonic() - started, 1)
            seconds.append(elapsed)
            verdict = outcome.verdict.verdict if outcome.verdict is not None else None
            severity = (
                int(outcome.verdict.severity_id)
                if outcome.verdict is not None
                else None
            )
            say(
                f"incident {incident_id} floor={item.severity_floor}"
                f" outcome={outcome.status} verdict={verdict} ({elapsed}s)"
            )
            per_incident.append(
                {
                    "incident_id": incident_id,
                    "floor": item.severity_floor,
                    "covers_day1": item.covers_day1,
                    "outcome": outcome.status,
                    "resumed": False,
                    "verdict": verdict,
                    "severity_id": severity,
                    "seconds": elapsed,
                }
            )
        if stopped_by is not None:
            notes.append(f"STOPPED: {stopped_by}")

        analyses = read_run_analyses(database_url, ids)
        analysis_rows = [row for row in analyses if row["stage"] == "analysis"]
        attempts = read_run_attempts(database_url, ids, run_started_at)

        from corvus.llm.price_book import load_price_book

        try:
            prices = load_price_book()
        except OSError, ValueError:
            prices = None
        attempt_summary = summarize_attempt_rows(attempts, prices)
        outcomes = count_outcomes(analysis_rows)

        timelines: dict[int, list[dict[str, Any]]] = {}
        blobs: list[str] = []
        incident_uids = read_incident_uids(database_url, ids)
        for row in analysis_rows:
            if row["status"] != "resolved":
                continue
            payload = row["payload"]
            # A stored resolved payload IS the verdict mapping
            # (``AnalysisVerdict.model_dump`` revealed on-prem).
            verdict_map = payload if isinstance(payload, dict) else {}
            timeline = verdict_map.get("timeline", [])
            if isinstance(timeline, list):
                timelines[int(row["incident_id"])] = [
                    {"event_uid": entry.get("event_uid")}
                    for entry in timeline
                    if isinstance(entry, dict)
                ]
            blobs.append(json.dumps(payload, sort_keys=True, default=str))
        uid_times = _uid_times(
            replay_dir, {uid for uids in incident_uids.values() for uid in uids}
        )
        chain = _chain_file()
        if chain is not None and timelines:
            in_run = [item.id for item in selected if item.id in timelines]
            ordered_timelines = {
                incident_id: timelines[incident_id] for incident_id in in_run
            }
            verdict_quality = timeline_step_coverage(
                chain, ordered_timelines, uid_times
            )
            attack = attack_accuracy(blobs, chain, labels_mode)
        else:
            verdict_quality = {
                "computed": False,
                "reason": "no chain file or no resolved timelines",
                "timelines_n": len(timelines),
            }
            attack = attack_accuracy(blobs, chain or {}, labels_mode)
        hallucinations = hallucinated_uids(timelines, incident_uids)

        resolved_main = [row for row in analysis_rows if row["status"] == "resolved"]
        floor_held_n = 0
        for row in analysis_rows:
            if row["status"] != "resolved":
                continue
            payload = row["payload"]
            inner = payload if isinstance(payload, dict) else {}
            severity = inner.get("severity_id")
            floor = row.get("deterministic_floor")
            if isinstance(severity, int) and isinstance(floor, int):
                if severity >= floor:
                    floor_held_n += 1
        benign_section: dict[str, Any] = {
            "measured": False,
            "reason": "no benign ground truth in this run; use --adversarial",
            "benign_n": 0,
            "marked_true_positive_n": 0,
        }

        wall = wall_stats(seconds)
        pending_ids = [item.id for item in selected if item.id not in set(analysis_ids)]
        total_floors = len(pending_ids)

        stored_texts = read_stored_texts(database_url, ids)
        deny_values = pseudonym_deny_values(database_url)
        stored_check = check_stored_texts(stored_texts, deny_values)
        leakage = {
            "request_bodies": {
                "computed": False,
                "reason": "cloud request bodies are captured via the transport"
                " in test mode only; this run scanned persisted texts",
            },
            "stored_texts": stored_check,
            "status": "fail" if stored_check["hits_n"] else "pass",
        }

        adv_section: dict[str, Any] | None = None
        if adversarial:
            if spent_usd(database_url) >= effective_cap:
                notes.append("adversarial skipped: spend cap already reached")
            else:
                fixtures = load_adversarial_fixtures()
                adv = run_adversarial(
                    database_url,
                    fixtures,
                    lang=lang,
                    labels_mode=labels_mode,
                    report_progress=say,
                )
                adv_section = adv
                benign_section = {
                    "measured": True,
                    "source": "adversarial benign fixtures",
                    "benign_n": adv["benign"]["benign_n"],
                    "marked_true_positive_n": adv["benign"]["marked_true_positive_n"],
                }

        firsts = [i.first_seen for i in selected if i.first_seen]
        lasts = [i.last_seen for i in selected if i.last_seen]
        results = {
            "meta": {
                "producing_command": producing_command
                or (
                    f"corvus eval llm --min-floor {min_floor}"
                    f" --analyze {analyze_n} --lang {lang}"
                    f" --labels {labels_mode}"
                    + (f" --max-usd {max_usd}" if max_usd is not None else "")
                    + (
                        f" --concurrency {concurrency}"
                        if concurrency is not None
                        else ""
                    )
                    + (" --adversarial" if adversarial else "")
                ),
                "git_commit": git_commit(),
                "generated_at": maintainer_today(),
                "dirty_tree": dirty_tree,
                "dirty_paths_n": dirty_paths_n,
                "data_window": {
                    "start": min(firsts) if firsts else None,
                    "end": max(lasts) if lasts else None,
                },
                "labels_mode": labels_mode,
                "selection_rule": rule,
                "coverage_note": coverage_note,
                "max_usd": max_usd,
                "spend_cap_usd": spend_cap,
                "effective_cap_usd": effective_cap,
                "spent_usd": round(spent_usd(database_url), 6),
                "runtime_seconds": round(time.monotonic() - wall_started, 1),
            },
            "n": {
                "selected": len(selected),
                "analyzed": len(analysis_ids),
                "attempt_rows": len(attempts),
            },
            "selection": [
                {
                    "incident_id": item.id,
                    "floor": item.severity_floor,
                    "event_n": item.event_count,
                    "covers_day1": item.covers_day1,
                    "correlation_key": item.correlation_key,
                }
                for item in selected
            ],
            "per_incident": per_incident,
            "skipped_resumed_n": skipped_n,
            "stopped_by": stopped_by,
            "triage_counts": dict(triage_counts),
            "outcomes": outcomes,
            "attempts": attempt_summary,
            "verdict_quality": verdict_quality,
            "hallucinations": hallucinations,
            "attack_accuracy": attack,
            "floor_hold": {
                "resolved_n": len(resolved_main),
                "held_n": floor_held_n,
            },
            "benign": benign_section,
            "wall": wall,
            "extrapolation": extrapolate_remaining(wall, total_floors),
            "leakage": leakage,
            "adversarial": adv_section,
        }
    finally:
        if previous_labels is None:
            os.environ.pop("DETECTOR_LABELS", None)
        else:
            os.environ["DETECTOR_LABELS"] = previous_labels
    exit_code = 0
    if results["leakage"]["status"] == "fail":
        exit_code = 1
        notes.append(
            f"FAIL leakage gate: n={stored_check['hits_n']} raw-value hit(s)"
            " in persisted texts"
        )
    else:
        notes.append(
            f"PASS leakage gate: {stored_check['texts_n']} persisted texts vs"
            f" {stored_check['values_n']} deny values, no hits;"
            " cloud bodies test-mode only"
        )
    return results, exit_code, notes


def render_llm_markdown(results: dict[str, Any]) -> str:
    """Render ``eval/reports/llm_latest.md`` (every number carries its n)."""
    meta = results["meta"]
    window = meta["data_window"]
    lines = [
        "# Corvus model-path eval (latest)",
        "",
        f"- date: {meta['generated_at']} (maintainer local, UTC-6)",
        f"- producing command: `{meta['producing_command']}`",
        f"- git commit: {meta['git_commit']}",
        f"- labels mode: {meta['labels_mode']}",
        f"- selection rule: {meta['selection_rule']}",
        f"- coverage: {meta['coverage_note']}",
        f"- data window: {window['start']} .. {window['end']}",
        f"- dirty tree: {meta['dirty_tree']} ({meta['dirty_paths_n']} paths)",
        f"- spend: {meta['spent_usd']} USD used of"
        f" {meta['effective_cap_usd']} effective cap"
        f" (max-usd {meta['max_usd']}, SPEND_CAP_USD"
        f" {meta['spend_cap_usd']})",
        f"- runtime: {meta['runtime_seconds']} s wall",
        "",
        "## Selection",
        "",
        f"- selected: n={results['n']['selected']};"
        f" analyzed: n={results['n']['analyzed']};"
        f" resumed-skipped: n={results['skipped_resumed_n']}",
        f"- stopped by: {results['stopped_by']}",
        "",
        "| incident | floor | events (n) | day-1 | outcome | verdict"
        " | severity | seconds |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    selected_by_id = {row["incident_id"]: row for row in results["selection"]}
    for row in results["per_incident"]:
        sel = selected_by_id.get(row["incident_id"], {})
        lines.append(
            f"| {row['incident_id']} | {row['floor']} |"
            f" {sel.get('event_n', '?')} | {row['covers_day1']} |"
            f" {row['outcome']} | {row['verdict']} | {row['severity_id']} |"
            f" {row['seconds']} |"
        )
    lines += ["", "## Outcomes (final analysis status, each with n)", ""]
    outcomes = results["outcomes"]
    lines.append(f"- incidents with an analysis row: n={outcomes['n']}")
    for status, count in outcomes["counts"].items():
        lines.append(f"- {status}: n={count}")
    lines += ["", "## Attempts per (model, purpose)", ""]
    for group in results["attempts"]:
        lines.append(
            f"- {group['model']} / {group['purpose']}:"
            f" calls n={group['n_calls']}, attempts n={group['n_attempts']},"
            f" first-pass validity {group['first_pass_validity']}"
            f" (n={group['first_pass_n']}), avg attempts"
            f" {group['avg_attempts']}, tokens per resolved"
            f" {group['tokens_per_resolved']} (n={group['resolved_n']}),"
            f" USD per resolved {group['usd_per_resolved']}"
        )
        for source, share in group["token_source_share"].items():
            lines.append(
                f"  - token_source {source}: n={share['n']}, share={share['share']}"
            )
    lines += ["", "## Verdict quality (APT29 day-1 timeline coverage)", ""]
    quality = results["verdict_quality"]
    if quality.get("computed", True) is False:
        lines.append(f"- not computed: {quality.get('reason')}")
    else:
        lines.append(
            f"- chain: {quality.get('chain_id')}; day-1 incident:"
            f" {quality.get('day1_incident_id')}; timelines"
            f" n={quality.get('timelines_n')}; steps"
            f" n={quality.get('steps_n')}; best covered"
            f" n={quality.get('best_covered_n')}; all covered"
            f" n={quality.get('all_covered_n')}; cited without store time"
            f" n={quality.get('cited_without_time_n')}"
        )
        lines += [
            "",
            "| step | name | techniques | best | all |",
            "| --- | --- | --- | --- | --- |",
        ]
        for step in quality.get("steps", []):
            lines.append(
                f"| {step['step']} | {step['name']} |"
                f" {','.join(step['techniques'])} | {step['covered_by_best']} |"
                f" {step['covered_by_all']} |"
            )
    hallucinations = results["hallucinations"]
    lines += [
        "",
        "## Cited event uids",
        "",
        f"- cited: n={hallucinations['cited_n']}; hallucinated"
        f" n={hallucinations['hallucinated_n']} (share"
        f" {hallucinations['hallucinated_share']})",
    ]
    attack = results["attack_accuracy"]
    lines += ["", "## ATT&CK mapping accuracy", ""]
    if not attack.get("computed", False):
        lines.append(
            f"- not computed ({attack.get('labels_mode')} mode): {attack.get('reason')}"
        )
    else:
        lines.append(
            f"- {attack['labels_mode']} mode;"
            f" limitation: {attack['limitation']}; emitted"
            f" n={attack['emitted_n']}, in ground"
            f" n={attack['emitted_in_ground_n']}, ground"
            f" n={attack['ground_n']}, ground covered"
            f" n={attack['ground_covered_n']}"
            f" ({','.join(attack['ground_covered'])})"
        )
    floor = results["floor_hold"]
    benign = results["benign"]
    lines += [
        "",
        "## Severity floor and benign set",
        "",
        f"- resolved verdicts holding the floor: {floor['held_n']}"
        f" of n={floor['resolved_n']}; a verdict never moves severity"
        " below the floor",
        f"- benign: measured={benign['measured']}"
        f" ({benign.get('reason', benign.get('source', ''))}); benign"
        f" n={benign['benign_n']}, marked true_positive"
        f" n={benign['marked_true_positive_n']}",
    ]
    wall = results["wall"]
    extra = results["extrapolation"]
    lines += [
        "",
        "## Wall time",
        "",
        f"- per incident: n={wall['n']}, median"
        f" {wall['median_seconds']} s, p90 {wall['p90_seconds']} s",
        f"- extrapolation (estimate): {extra['remaining_n']} remaining"
        f" incidents at the median: {extra['estimated_seconds']} s"
        f" ({extra['note']})",
    ]
    leakage = results["leakage"]
    stored = leakage["stored_texts"]
    lines += [
        "",
        "## Anti-leakage",
        "",
        f"- status: {leakage['status']}",
        f"- cloud request bodies: {leakage['request_bodies']['reason']}",
        f"- persisted texts: {stored['texts_n']} texts vs"
        f" {stored['values_n']} deny values, hits n={stored['hits_n']}",
    ]
    for hit in stored["hits"]:
        lines.append(f"- {hit}")
    adv = results.get("adversarial")
    lines += ["", "## Adversarial", ""]
    if adv is None:
        lines.append("- not run (pass --adversarial to run the fixture set).")
    else:
        change = adv["verdict_change"]
        quarantine = adv["quarantine"]
        floor_adv = adv["floor"]
        benign_adv = adv["benign"]
        detector = adv["detector"]
        lines += [
            f"- fixtures: n={adv['fixtures_n']}",
            f"- verdict change: {change['changed_n']} of pairs"
            f" n={change['pairs_n']} (share {change['share']})",
            f"- quarantine: {quarantine['quarantined_n']} of payload"
            f" n={quarantine['payload_n']} (share {quarantine['share']})",
            f"- floor held: {floor_adv['held_n']} of resolved"
            f" n={floor_adv['resolved_n']}",
            f"- benign marked true_positive: {benign_adv['marked_true_positive_n']}"
            f" of n={benign_adv['benign_n']}",
            f"- detector flagged: {detector['flagged_fixtures_n']} of"
            f" n={detector['fixtures_n']} fixtures",
            "",
            "| fixture | kind | triage | analysis | verdict | floor"
            " held | detector flagged (n) | seconds |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for row in adv["fixtures"]:
            lines.append(
                f"| {row['fixture_id']} | {row['kind']} |"
                f" {row['triage_status']} | {row['analysis_status']} |"
                f" {row['verdict']} | {row['floor_held']} |"
                f" {row['detector']['flagged_n']} | {row['seconds']} |"
            )
    lines += [
        "",
        "## Cost bound",
        "",
        f"- worst-case single-incident Spark cost:"
        f" {WORST_CASE_ANALYSIS_USD:.4f} USD (analysis caps at published"
        " muse-spark-1.3 prices, zero cache hits; Glimmer is 0 USD).",
        f"- bound for this selection: {results['n']['analyzed']} analyzed x"
        f" {WORST_CASE_ANALYSIS_USD:.4f} ="
        f" {results['n']['analyzed'] * WORST_CASE_ANALYSIS_USD:.2f} USD max.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``corvus eval llm``; writes llm_latest.md/json."""
    parser = argparse.ArgumentParser(prog="corvus eval llm", description=__doc__)
    parser.add_argument("--min-floor", type=int, default=4)
    parser.add_argument("--analyze", type=int, default=1)
    parser.add_argument("--lang", default="en", choices=["en", "es"])
    parser.add_argument("--labels", default="blind", choices=["visible", "blind"])
    parser.add_argument("--max-usd", type=float, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--adversarial", action="store_true")
    parser.add_argument("--replay-dir", default=str(DEFAULT_REPLAY_DIR))
    parser.add_argument("--report-md", default=str(DEFAULT_REPORT_MD))
    parser.add_argument("--report-json", default=str(DEFAULT_REPORT_JSON))
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    args = parser.parse_args(argv)
    if not args.database_url:
        print("error: DATABASE_URL is not set (or pass --database-url).")
        return 2
    producing = (
        f"corvus eval llm --min-floor {args.min_floor}"
        f" --analyze {args.analyze} --lang {args.lang}"
        f" --labels {args.labels}"
        + (f" --max-usd {args.max_usd}" if args.max_usd is not None else "")
        + (f" --concurrency {args.concurrency}" if args.concurrency else "")
        + (" --adversarial" if args.adversarial else "")
    )
    results, exit_code, notes = run_llm_eval(
        args.database_url,
        min_floor=args.min_floor,
        analyze_n=args.analyze,
        lang=args.lang,
        labels_mode=args.labels,
        max_usd=args.max_usd,
        replay_dir=Path(args.replay_dir),
        concurrency=args.concurrency,
        adversarial=args.adversarial,
        report_progress=print,
        producing_command=producing,
    )
    report_md = Path(args.report_md)
    report_json = Path(args.report_json)
    report_md.parent.mkdir(parents=True, exist_ok=True)
    report_md.write_text(render_llm_markdown(results), encoding="utf-8")
    report_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {report_md} and {report_json}")
    for note in notes:
        print(note)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
