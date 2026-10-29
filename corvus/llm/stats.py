"""Metrics computed from ``llm_attempts`` rows.

All functions here are pure: they take rows as mappings (as read
from ``llm_attempts``, with ``call_id``, ``model``, ``purpose``,
``attempt_number``, ``failed_validator``, ``outcome`` and the token
columns) and return plain data. Every number carries its ``n`` —
the count of calls or attempts it was computed over.

Per (model, purpose) group:

- calls (``n_calls``) and attempts (``n_attempts``),
- first-pass validity rate: share of calls whose attempt 1 has no
  failed validator,
- average attempts per call,
- final failure rate: share of calls with no ``ok`` attempt,
- tokens and USD per resolved call (resolved = at least one
  ``ok`` attempt; USD via the price book over every attempt of the
  resolved calls).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from corvus.llm.price_book import ModelPrice, cost_usd

__all__ = ["summarize_attempt_rows"]

_REQUIRED_KEYS = frozenset(
    {
        "call_id",
        "model",
        "purpose",
        "attempt_number",
        "failed_validator",
        "outcome",
        "prompt_tokens",
        "cached_tokens",
        "reasoning_tokens",
        "answer_tokens",
        "overhead_tokens",
    }
)


def _tokens_out(row: Mapping[str, Any]) -> int:
    """Completion tokens: reasoning + answer + overhead."""
    return (
        int(row["reasoning_tokens"])
        + int(row["answer_tokens"])
        + int(row["overhead_tokens"])
    )


def _usd_for_row(row: Mapping[str, Any], prices: Mapping[str, ModelPrice]) -> float:
    """USD cost of one attempt row under the price book."""
    return cost_usd(
        prices,
        str(row["model"]),
        int(row["prompt_tokens"]),
        int(row["cached_tokens"]),
        _tokens_out(row),
    )


def summarize_attempt_rows(
    rows: Sequence[Mapping[str, Any]],
    prices: Mapping[str, ModelPrice] | None = None,
) -> list[dict[str, Any]]:
    """Summarize attempt rows per (model, purpose), sorted by key.

    Raises :class:`KeyError` when a row lacks a required key and
    :class:`corvus.llm.price_book.PriceBookError` when USD is
    requested for an unpriced model.
    """
    for position, row in enumerate(rows):
        missing = _REQUIRED_KEYS - set(row.keys())
        if missing:
            raise KeyError(f"row {position} is missing keys: {sorted(missing)}")
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        key = (str(row["model"]), str(row["purpose"]))
        groups.setdefault(key, []).append(row)
    summaries: list[dict[str, Any]] = []
    for model, purpose in sorted(groups):
        members = groups[(model, purpose)]
        by_call: dict[str, list[Mapping[str, Any]]] = {}
        for row in members:
            by_call.setdefault(str(row["call_id"]), []).append(row)
        n_calls = len(by_call)
        n_attempts = len(members)
        first_rows = [
            attempts
            for attempts in (
                [row for row in rows if int(row["attempt_number"]) == 1]
                for rows in by_call.values()
            )
            if attempts
        ]
        n_first = len(first_rows)
        first_valid = sum(
            1 for attempt in first_rows if attempt[0]["failed_validator"] is None
        )
        resolved = {
            call_id
            for call_id, attempts in by_call.items()
            if any(row["outcome"] == "ok" for row in attempts)
        }
        n_resolved = len(resolved)
        tokens_total = 0
        usd_total = 0.0
        usd_known = prices is not None
        for call_id in resolved:
            for row in by_call[call_id]:
                tokens_total += int(row["prompt_tokens"]) + _tokens_out(row)
                if prices is not None:
                    usd_total += _usd_for_row(row, prices)
        summaries.append(
            {
                "model": model,
                "purpose": purpose,
                "n_calls": n_calls,
                "n_attempts": n_attempts,
                "first_pass_validity": {
                    "rate": (first_valid / n_first) if n_first else None,
                    "n": n_first,
                },
                "average_attempts": {
                    "value": (n_attempts / n_calls) if n_calls else None,
                    "n": n_calls,
                },
                "final_failure_rate": {
                    "rate": ((n_calls - n_resolved) / n_calls) if n_calls else None,
                    "n": n_calls,
                },
                "tokens_per_resolved_call": {
                    "value": (tokens_total / n_resolved) if n_resolved else None,
                    "n": n_resolved,
                },
                "usd_per_resolved_call": {
                    "value": (usd_total / n_resolved)
                    if (n_resolved and usd_known)
                    else None,
                    "n": n_resolved,
                },
            }
        )
    return summaries
