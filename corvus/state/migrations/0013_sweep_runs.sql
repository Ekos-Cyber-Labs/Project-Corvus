-- Migration 013: automatic sweep runs (Postgres stays the system of record).
-- Plain SQL, idempotent: safe to execute twice. All timestamps are
-- TIMESTAMPTZ (timezone-aware UTC).
--
-- A sweep run is one poll cycle plus deterministic policy selection
-- plus sequential triage/Spark analysis of the selected incidents.
-- Alert/incident counts already live on the linked wazuh_poll_cycles
-- row, so they are NOT duplicated here: sweep_runs.poll_cycle_id
-- points at that row and the API reads counts through the join.
-- Only sweep-specific numbers (analyzed/failed/skipped) and the
-- effective policy live here. No credentials, raw events, or request
-- bodies are stored.

CREATE TABLE IF NOT EXISTS sweep_runs (
    id BIGSERIAL PRIMARY KEY,
    poll_cycle_id BIGINT REFERENCES wazuh_poll_cycles (id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'ok', 'failed')),
    error_code TEXT NOT NULL DEFAULT '',
    analyzed INTEGER NOT NULL DEFAULT 0 CHECK (analyzed >= 0),
    failed_analyses INTEGER NOT NULL DEFAULT 0 CHECK (failed_analyses >= 0),
    skipped_policy INTEGER NOT NULL DEFAULT 0 CHECK (skipped_policy >= 0),
    skipped_budget INTEGER NOT NULL DEFAULT 0 CHECK (skipped_budget >= 0),
    policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    interval_seconds DOUBLE PRECISION NOT NULL DEFAULT 300 CHECK (interval_seconds >= 30)
);

CREATE TABLE IF NOT EXISTS sweep_decisions (
    sweep_run_id BIGINT NOT NULL REFERENCES sweep_runs (id) ON DELETE CASCADE,
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    decision TEXT NOT NULL
        CHECK (decision IN ('analyze', 'skipped_policy', 'skipped_budget')),
    reason_code TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (sweep_run_id, incident_id)
);

CREATE INDEX IF NOT EXISTS idx_sweep_runs_started
    ON sweep_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sweep_decisions_incident
    ON sweep_decisions (incident_id);
