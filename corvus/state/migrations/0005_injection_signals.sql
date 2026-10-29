-- Migration 005: injection signals, security events, review flag.
-- Plain SQL, idempotent: safe to execute twice. All timestamps are
-- TIMESTAMPTZ (timezone-aware UTC).
--
-- A deterministic prompt-injection hit is a signal of the incident
-- itself (see corvus/guardrails/injection.py), never a severity
-- change: signals do not move severity_floor or severity_id, they
-- only raise incidents.review_required for later prompts (the
-- analyst prompt and the future security validator read the flag
-- plus the signal rows as a fact).
--
-- incident_signals stores one row per natural key (incident, kind,
-- event, field, pattern, requested effect); re-scans upsert on that
-- key and merge spans in detail instead of duplicating rows. detail
-- carries {"spans": [[start, end], ...], "excerpt": ...,
-- "normalized_len": ...} with offsets into the normalized
-- space-collapsed field text.
-- security_events is the append-only log the future security
-- validator quarantines into (validator failures are never retried).
-- incident_id stays nullable: some security events (transport or
-- egress blocks) belong to no incident.

-- Later prompts read this flag alongside the signal rows.
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS review_required BOOLEAN NOT NULL DEFAULT FALSE;

-- One detected signal per natural key (re-scans do not duplicate).
CREATE TABLE IF NOT EXISTS incident_signals (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    event_uid TEXT NOT NULL,
    field TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    requested_effect TEXT NOT NULL
        CHECK (requested_effect IN ('suppress', 'inflate', 'exfiltrate', 'other')),
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (incident_id, kind, event_uid, field, pattern_id, requested_effect)
);

-- Append-only security log for the future validator (no UNIQUE:
-- repeated quarantines of the same incident are separate events).
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT REFERENCES incidents (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_signals_incident
    ON incident_signals (incident_id);
CREATE INDEX IF NOT EXISTS idx_security_events_incident
    ON security_events (incident_id, created_at DESC);
