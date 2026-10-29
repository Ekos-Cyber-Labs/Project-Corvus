-- Migration 003: explainable severity factors on incidents.
-- Plain SQL, idempotent: safe to execute twice. The deterministic
-- correlation already returns ``severity_factors`` with every
-- incident (factors 1, 2 and 4 with per-factor explanations, see
-- ``corvus/correlate``); this column persists that explanation next
-- to the floor it justifies.
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS severity_factors JSONB NOT NULL DEFAULT '{}'::jsonb;
