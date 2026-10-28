FROM python:3.12-slim
RUN useradd --create-home --uid 10001 corvus
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY corvus ./corvus
RUN uv sync --frozen --no-dev && chown -R corvus:corvus /app
USER corvus
ENV PATH="/app/.venv/bin:${PATH}"
EXPOSE 8000
