.PHONY: install lint test up down ui-build ui-test

install:
	uv sync --group dev

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy corvus

test:
	uv run pytest -q

ui-build:
	cd ui && npm ci && npm run build

ui-test:
	cd ui && npm ci && npm test

up:
	docker compose up --build -d

down:
	docker compose down
