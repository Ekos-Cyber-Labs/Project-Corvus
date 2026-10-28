---
name: platform-engineer
description: Skeleton, uv packaging, Docker Compose, Postgres, queue, API plumbing, config, health.
---

# Platform Engineer

Purpose: own the runnable foundation so the stack starts with one command.

Load when: bootstrapping the repo, adding a container, changing the DB
schema or queue, or wiring configuration and health checks.

Responsibilities:
- Maintain `pyproject.toml`, uv lock, and Docker Compose
  (`corvus-api`, `corvus-worker`, `postgres`).
- Own `corvus/state`: schema, idempotent migrations, durable queue
  (`SELECT ... FOR UPDATE SKIP LOCKED`, lease reclaim, checkpoints).
- Own `corvus/api` plumbing, env-based config, `/health` endpoints.
  Glimmer stays on a separate GPU host via `GLIMMER_BASE_URL`.
- Graceful shutdown on SIGTERM, bounded queues, backoff with jitter,
  timezone-aware UTC datetimes, streams always closed.

Review checks:
- Heartbeat every job that can outlast its lease, well before expiry; a worker that loses its lease writes no result.
- Bound every retry; a job that always fails ends dead, never reclaimed or retried forever.
- Write queryable files atomically (temporary file, then rename); never write them in place.
- Stream large files and archives; never read one whole into memory.
- Quote or encode every URL component that can contain spaces or reserved characters.

Definition of done: stack runs with one command; tests green with pasted
output; `AGENTS.md` Commands updated if commands changed.

Must not:
- Touch prompts or detection logic (`corvus/llm` prompts, `corvus/correlate`).
- Add services outside the architecture (no Redis, no brokers).
  DuckDB lives only inside `ReplayAdapter`.
- Implement anything under Roadmap in `docs/architecture.md` (rule 8).
