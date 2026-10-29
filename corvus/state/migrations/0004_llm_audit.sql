-- Migration 004: LLM audit columns, incident analyses, spend reservations.
-- Plain SQL, idempotent: safe to execute twice. All timestamps are
-- TIMESTAMPTZ (timezone-aware UTC).
--
-- llm_attempts.reasoning is the audit-only trace of what the model
-- considered (D24): it stays on-prem next to the attempt counts and is
-- never part of the pseudonymized payload sent to Muse Spark.
-- llm_attempts.token_source records how exact the token split of the
-- attempt is: 'exact_ids' (Glimmer token ids split by channel headers),
-- 'usage' (provider-reported usage), or 'estimated'.
-- incident_analyses stores one deterministic row per (incident, stage):
-- the triage and analysis verdicts plus the severity floor they were
-- checked against. spend_reservations backs the USD budget guard in
-- corvus/llm/spend.py: a held reservation counts against the cap until
-- it is converted into spend or released, and expires_at frees the
-- budget when a worker crashes before finishing the call.

-- Audit-only reasoning trace (nullable: older rows and providers that
-- report usage only carry no reasoning text).
ALTER TABLE llm_attempts
    ADD COLUMN IF NOT EXISTS reasoning TEXT;

-- Token-count provenance. NULL passes a CHECK (NULL is not false), so
-- older rows without provenance stay valid.
ALTER TABLE llm_attempts
    ADD COLUMN IF NOT EXISTS token_source TEXT
    CHECK (token_source IN ('exact_ids', 'usage', 'estimated'));

-- One analysis verdict per (incident, stage). Stages mirror the model
-- call purposes; statuses mirror the incident ai_status lifecycle plus
-- the security-validator quarantine outcome.
CREATE TABLE IF NOT EXISTS incident_analyses (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    stage TEXT NOT NULL
        CHECK (stage IN ('triage', 'analysis')),
    status TEXT NOT NULL
        CHECK (status IN ('resolved', 'indeterminate', 'unprocessed',
                          'ai_failed', 'pending_ai', 'quarantined')),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    language TEXT,
    model TEXT,
    deterministic_floor INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (incident_id, stage)
);

-- Pre-call USD budget reservations (see corvus/llm/spend.py). A row is
-- active while status is 'held' and expires_at is in the future;
-- converting records the real spend, releasing frees the hold.
CREATE TABLE IF NOT EXISTS spend_reservations (
    id BIGSERIAL PRIMARY KEY,
    amount_usd NUMERIC(12, 6) NOT NULL CHECK (amount_usd >= 0),
    status TEXT NOT NULL DEFAULT 'held'
        CHECK (status IN ('held', 'converted', 'released')),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_analyses_incident
    ON incident_analyses (incident_id, stage);
CREATE INDEX IF NOT EXISTS idx_spend_reservations_active
    ON spend_reservations (status, expires_at);
