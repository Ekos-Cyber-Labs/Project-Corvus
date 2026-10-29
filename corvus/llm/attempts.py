"""Durable record of one model attempt.

:func:`record_attempt` inserts one row into ``llm_attempts`` (call and
attempt identity, validator outcome, the exact token fields with
their provenance, latency, outcome, audit reasoning) and, for billed
backends, converts the pre-call budget reservation into its spend row
through :func:`corvus.llm.spend.convert_reservation`. Attempt row,
conversion and spend row run in ONE Postgres transaction: either all
land or none does. Nothing is swallowed — when Postgres rejects the
write the error propagates to the caller.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any, Literal

import psycopg
from psycopg.types.json import Jsonb

from corvus.llm.price_book import ModelPrice
from corvus.llm.spend import ConversionResult, convert_reservation
from corvus.llm.transport import TokenSource

TokenSources: tuple[str, str, str] = ("exact_ids", "usage", "estimated")

DATABASE_URL_VAR = "DATABASE_URL"


def _database_url(explicit: str | None) -> str:
    url = explicit or os.environ.get(DATABASE_URL_VAR)
    if not url:
        raise ValueError(
            f"missing database URL: pass database_url or set {DATABASE_URL_VAR}"
        )
    return url


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string, got {value!r}")
    return value


def _require_optional_text(name: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string or None, got {value!r}")
    return value


def _require_count(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int, got {value!r}")
    return value


def _require_error_entry(entry: object) -> str | dict[str, Any]:
    """Validate one ``errors`` entry: a string or a string-keyed mapping."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, Mapping) and all(isinstance(key, str) for key in entry):
        return dict(entry)
    raise ValueError(
        f"errors entries must be strings or mappings with string keys, got {entry!r}"
    )


def record_attempt(
    *,
    call_id: str,
    incident_id: int | None,
    model: str,
    purpose: str,
    attempt_number: int,
    failed_validator: str | None,
    errors: Sequence[str | Mapping[str, Any]],
    prompt_tokens: int,
    cached_tokens: int,
    reasoning_tokens: int,
    answer_tokens: int,
    overhead_tokens: int,
    token_source: TokenSource,
    latency_ms: int | None,
    outcome: str,
    reasoning: str | None,
    billed: bool,
    reservation_id: int | None,
    database_url: str | None = None,
    prices: Mapping[str, ModelPrice] | None = None,
) -> tuple[int, ConversionResult | None]:
    """Insert one ``llm_attempts`` row plus, when billed, its spend.

    ``billed`` is True for cloud backends (their tokens cost money)
    and False for on-prem inference, which converts nothing. Spend
    always goes through the pre-call reservation exactly once: when
    billed, ``reservation_id`` is required and the attempt row, the
    reservation conversion and its spend row are written in ONE
    Postgres transaction; when unbilled, ``reservation_id`` must be
    None and no spend row is written. ``errors`` is stored as a JSON
    array of the passed strings and mappings. Range checks
    (non-negative counts, ``attempt_number >= 1``, valid
    ``token_source``) are enforced by the Postgres CHECK constraints;
    violations raise instead of being swallowed. Returns the new
    ``llm_attempts`` id plus the conversion result (None unbilled).
    """
    _require_text("call_id", call_id)
    _require_text("model", model)
    _require_text("purpose", purpose)
    _require_text("outcome", outcome)
    if incident_id is not None and (
        isinstance(incident_id, bool) or not isinstance(incident_id, int)
    ):
        raise ValueError(f"incident_id must be an int or None, got {incident_id!r}")
    _require_count("attempt_number", attempt_number)
    _require_optional_text("failed_validator", failed_validator)
    if isinstance(errors, (str, bytes, Mapping)) or not isinstance(errors, Sequence):
        raise ValueError(
            f"errors must be a sequence of strings or mappings, got {errors!r}"
        )
    error_list = [_require_error_entry(entry) for entry in errors]
    prompt_tokens = _require_count("prompt_tokens", prompt_tokens)
    cached_tokens = _require_count("cached_tokens", cached_tokens)
    reasoning_tokens = _require_count("reasoning_tokens", reasoning_tokens)
    answer_tokens = _require_count("answer_tokens", answer_tokens)
    overhead_tokens = _require_count("overhead_tokens", overhead_tokens)
    if token_source not in TokenSources:
        raise ValueError(
            f"token_source must be one of {TokenSources}, got {token_source!r}"
        )
    source: Literal["exact_ids", "usage", "estimated"] = token_source
    if latency_ms is not None:
        _require_count("latency_ms", latency_ms)
    _require_optional_text("reasoning", reasoning)
    if not isinstance(billed, bool):
        raise ValueError(f"billed must be a bool, got {billed!r}")
    if billed:
        if reservation_id is None:
            raise ValueError("billed attempts require reservation_id")
        if isinstance(reservation_id, bool) or not isinstance(reservation_id, int):
            raise ValueError(f"reservation_id must be an int, got {reservation_id!r}")
    elif reservation_id is not None:
        raise ValueError("unbilled attempts must pass reservation_id=None")
    url = _database_url(database_url)
    tokens_out = reasoning_tokens + answer_tokens + overhead_tokens
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO llm_attempts (call_id, incident_id, model, "
                "purpose, attempt_number, failed_validator, errors, "
                "prompt_tokens, cached_tokens, reasoning_tokens, "
                "answer_tokens, overhead_tokens, latency_ms, outcome, "
                "token_source, reasoning) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                "%s, %s, %s, %s) RETURNING id",
                (
                    call_id,
                    incident_id,
                    model,
                    purpose,
                    attempt_number,
                    failed_validator,
                    Jsonb(error_list),
                    prompt_tokens,
                    cached_tokens,
                    reasoning_tokens,
                    answer_tokens,
                    overhead_tokens,
                    latency_ms,
                    outcome,
                    source,
                    reasoning,
                ),
            )
            row = cur.fetchone()
            assert row is not None
            attempt_id = int(row[0])
            conversion: ConversionResult | None = None
            if billed:
                assert reservation_id is not None
                conversion = convert_reservation(
                    reservation_id,
                    model,
                    prompt_tokens,
                    cached_tokens,
                    tokens_out,
                    incident_id,
                    prices=prices,
                    conn=conn,
                )
        conn.commit()
    return attempt_id, conversion
