.PHONY: install lint test up down

install:
	uv sync --group dev

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy corvus

test:
	uv run pytest -q

up:
	docker compose up --build -d

down:
	docker compose down
