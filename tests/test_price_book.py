"""Price book strict loading and known-mix cost math."""

from pathlib import Path

import pytest

from corvus.llm.price_book import (
    DEFAULT_PRICE_BOOK_PATH,
    PriceBookError,
    cost_usd,
    load_price_book,
)


def test_committed_price_book_rates() -> None:
    prices = load_price_book()
    assert DEFAULT_PRICE_BOOK_PATH.name == "price_book.yaml"
    spark = prices["muse-spark-1.3"]
    assert (spark.input_per_mtok, spark.cached_input_per_mtok) == (1.25, 0.15)
    assert spark.output_per_mtok == 4.25
    assert spark.source == "published Meta pricing"
    assert spark.date == "2026-10-28"
    glimmer = prices["glimmer"]
    assert (glimmer.input_per_mtok, glimmer.cached_input_per_mtok) == (0, 0)
    assert glimmer.output_per_mtok == 0
    assert glimmer.note == "on-prem: electricity not included"


def test_known_token_mix_cost() -> None:
    prices = load_price_book()
    # 800 fresh + 200 cached input tokens, 500 output tokens.
    assert cost_usd(prices, "muse-spark-1.3", 1000, 200, 500) == pytest.approx(0.003155)
    assert cost_usd(prices, "glimmer", 10000, 1000, 5000) == 0.0


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "price_book.yaml"
    path.write_text(text, encoding="utf-8")
    return path


_GOOD = """\
muse-spark-1.3:
  input_per_mtok: 1.25
  cached_input_per_mtok: 0.15
  output_per_mtok: 4.25
  source: "published Meta pricing"
  date: "2026-10-28"
glimmer:
  input_per_mtok: 0
  cached_input_per_mtok: 0
  output_per_mtok: 0
  source: "on-prem"
  date: "2026-10-28"
"""


def test_unknown_keys_raise(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _GOOD.replace('source: "on-prem"', 'source: "on-prem"\n  bogus: 1'),
    )
    with pytest.raises(PriceBookError, match="unknown keys"):
        load_price_book(path)


def test_negative_numbers_raise(tmp_path: Path) -> None:
    path = _write(
        tmp_path, _GOOD.replace("output_per_mtok: 4.25", "output_per_mtok: -1")
    )
    with pytest.raises(PriceBookError, match="must not be negative"):
        load_price_book(path)


def test_missing_models_raise(tmp_path: Path) -> None:
    path = _write(tmp_path, _GOOD.split("glimmer:")[0])
    with pytest.raises(PriceBookError, match="missing models"):
        load_price_book(path)


def test_missing_keys_raise(tmp_path: Path) -> None:
    path = _write(tmp_path, _GOOD.replace('  date: "2026-10-28"\n', "", 1))
    with pytest.raises(PriceBookError, match="missing keys"):
        load_price_book(path)


def test_non_mapping_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(PriceBookError, match="must map model names"):
        load_price_book(path)


def test_non_finite_rate_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path, _GOOD.replace("output_per_mtok: 4.25", "output_per_mtok: .inf")
    )
    with pytest.raises(PriceBookError, match="must be finite"):
        load_price_book(path)


def test_cost_rejects_bad_inputs() -> None:
    prices = load_price_book()
    with pytest.raises(PriceBookError, match="unknown model"):
        cost_usd(prices, "nope", 1, 0, 1)
    with pytest.raises(PriceBookError, match="must not be negative"):
        cost_usd(prices, "muse-spark-1.3", -1, 0, 0)
    with pytest.raises(PriceBookError, match="exceeds tokens_in"):
        cost_usd(prices, "muse-spark-1.3", 10, 11, 0)
