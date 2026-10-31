# UI stage: build the static SPA (pinned in ui/package.json, verified 2026-10-30).
FROM node:22 AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# 3.14, not 3.15: duckdb 2.0.0 publishes no cp315 wheel yet (checked 2026-10-28).
FROM python:3.14-slim
RUN useradd --create-home --uid 10001 corvus
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY corvus ./corvus
COPY --from=ui /ui/dist ./ui/dist
RUN uv sync --frozen --no-dev && chown -R corvus:corvus /app
USER corvus
ENV PATH="/app/.venv/bin:${PATH}"
EXPOSE 8000
