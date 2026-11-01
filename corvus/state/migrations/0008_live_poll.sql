-- Migration 008: live-poll support (Postgres stays the system of record).
-- Plain SQL, idempotent: safe to execute twice. All timestamps are
-- TIMESTAMPTZ (timezone-aware UTC).
--
-- incidents.learned_rules is the read-only attribution the live poll
-- writes: a JSONB array with one entry per learned rule behind the
-- incident's findings (rule record id, Sigma id, version, mode
-- shadow/active, lineage id, native rule id, shadow/unknown flags).
-- Older rows (replay correlation) carry the default empty array.
-- wazuh_poll_cycles is the per-cycle bookkeeping for
-- `corvus wazuh poll` (counts only, never credentials, raw events,
-- or request bodies), so the proof of learned-rule findings does not
-- depend on log scraping.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS learned_rules JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS wazuh_poll_cycles (
    id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    alerts_seen INTEGER NOT NULL DEFAULT 0 CHECK (alerts_seen >= 0),
    events_written INTEGER NOT NULL DEFAULT 0 CHECK (events_written >= 0),
    findings_written INTEGER NOT NULL DEFAULT 0 CHECK (findings_written >= 0),
    learned_findings INTEGER NOT NULL DEFAULT 0 CHECK (learned_findings >= 0),
    shadow_findings INTEGER NOT NULL DEFAULT 0 CHECK (shadow_findings >= 0),
    unknown_learned INTEGER NOT NULL DEFAULT 0 CHECK (unknown_learned >= 0),
    incidents_upserted INTEGER NOT NULL DEFAULT 0 CHECK (incidents_upserted >= 0),
    archives_added INTEGER NOT NULL DEFAULT 0 CHECK (archives_added >= 0),
    cursor JSONB NOT NULL DEFAULT '{}'::jsonb,
    note TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_poll_cycles_started
    ON wazuh_poll_cycles (started_at DESC);
