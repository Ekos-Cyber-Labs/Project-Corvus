"""Static per-token price book for model spend accounting.

Prices live in ``config/price_book.yaml`` as USD per million tokens
(input, cached input, output) with a ``source`` and ``date`` per row.
Loading is strict: unknown keys, negative or non-numeric prices, and a
missing ``muse-spark-1.3`` or ``glimmer`` row all raise
:class:`PriceBookError`.

Cost semantics: ``tokens_in`` counts all input tokens and
``tokens_cached`` counts the subset of those served from cache, so the
fresh-input share is ``tokens_in - tokens_cached``::

    usd = ((tokens_in - tokens_cached) * input_per_mtok
           + tokens_cached * cached_input_per_mtok
           + tokens_out * output_per_mtok) / 1_000_000

Example: 1000 input tokens with 200 cached plus 500 output tokens on
``muse-spark-1.3`` costs
``(800 * 1.25 + 200 * 0.15 + 500 * 4.25) / 1e6 = 0.003155`` USD.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_PRICE_BOOK_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "price_book.yaml"
)

REQUIRED_MODELS = ("muse-spark-1.3", "glimmer")
REQUIRED_KEYS = frozenset(
    {
        "input_per_mtok",
        "cached_input_per_mtok",
        "output_per_mtok",
        "source",
        "date",
    }
)
OPTIONAL_KEYS = frozenset({"note"})
TOKENS_PER_MILLION = 1_000_000


class PriceBookError(ValueError):
    """Raised when the price book is missing, malformed or incomplete."""


@dataclass(frozen=True)
class ModelPrice:
    """USD-per-million-tokens rates plus provenance for one model."""

    model: str
    input_per_mtok: float
    cached_input_per_mtok: float
    output_per_mtok: float
    source: str
    date: str
    note: str | None = None


def load_price_book(path: str | Path | None = None) -> dict[str, ModelPrice]:
    """Load and strictly validate the price book YAML mapping."""
    resolved = Path(path) if path is not None else DEFAULT_PRICE_BOOK_PATH
    try:
        raw_text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise PriceBookError(f"cannot read price book at {resolved}: {exc}") from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PriceBookError(f"invalid YAML in price book at {resolved}") from exc
    if not isinstance(data, dict):
        raise PriceBookError(
            f"price book at {resolved} must map model names to rows, "
            f"got {type(data).__name__}"
        )
    prices: dict[str, ModelPrice] = {}
    for model, row in data.items():
        if not isinstance(model, str) or not model.strip():
            raise PriceBookError("price book model names must be non-empty strings")
        if not isinstance(row, dict):
            raise PriceBookError(f"price book row for {model!r} must be a mapping")
        unknown = set(row) - REQUIRED_KEYS - OPTIONAL_KEYS
        if unknown:
            raise PriceBookError(
                f"price book row for {model!r} has unknown keys: {sorted(unknown)}"
            )
        missing = REQUIRED_KEYS - set(row)
        if missing:
            raise PriceBookError(
                f"price book row for {model!r} is missing keys: {sorted(missing)}"
            )
        rates: dict[str, float] = {}
        for key in (
            "input_per_mtok",
            "cached_input_per_mtok",
            "output_per_mtok",
        ):
            value = row[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise PriceBookError(
                    f"price book row for {model!r}: {key} must be a "
                    f"number, got {value!r}"
                )
            if not math.isfinite(value):
                raise PriceBookError(
                    f"price book row for {model!r}: {key} must be finite, got {value!r}"
                )
            if value < 0:
                raise PriceBookError(
                    f"price book row for {model!r}: {key} must not be "
                    f"negative, got {value!r}"
                )
            rates[key] = float(value)
        for key in ("source", "date"):
            value = row[key]
            if not isinstance(value, str) or not value.strip():
                raise PriceBookError(
                    f"price book row for {model!r}: {key} must be a non-empty string"
                )
        note = row.get("note")
        if note is not None and not isinstance(note, str):
            raise PriceBookError(
                f"price book row for {model!r}: note must be a string, got {note!r}"
            )
        prices[model] = ModelPrice(
            model=model,
            input_per_mtok=rates["input_per_mtok"],
            cached_input_per_mtok=rates["cached_input_per_mtok"],
            output_per_mtok=rates["output_per_mtok"],
            source=row["source"].strip(),
            date=row["date"].strip(),
            note=note,
        )
    missing_models = [name for name in REQUIRED_MODELS if name not in prices]
    if missing_models:
        raise PriceBookError(
            f"price book at {resolved} is missing models: {missing_models}"
        )
    return prices


def cost_usd(
    prices: Mapping[str, ModelPrice],
    model: str,
    tokens_in: int,
    tokens_cached: int,
    tokens_out: int,
) -> float:
    """Return the USD cost of a token mix under ``prices``."""
    if model not in prices:
        raise PriceBookError(
            f"unknown model {model!r}; price book carries {sorted(prices)}"
        )
    for name, value in (
        ("tokens_in", tokens_in),
        ("tokens_cached", tokens_cached),
        ("tokens_out", tokens_out),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise PriceBookError(f"{name} must be an int, got {value!r}")
        if value < 0:
            raise PriceBookError(f"{name} must not be negative, got {value!r}")
    if tokens_cached > tokens_in:
        raise PriceBookError(
            f"tokens_cached ({tokens_cached}) exceeds tokens_in "
            f"({tokens_in}): cached tokens are a subset of input tokens"
        )
    rate = prices[model]
    return (
        (tokens_in - tokens_cached) * rate.input_per_mtok
        + tokens_cached * rate.cached_input_per_mtok
        + tokens_out * rate.output_per_mtok
    ) / TOKENS_PER_MILLION
