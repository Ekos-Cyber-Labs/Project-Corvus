-- Migration 006: per-step tool scope for the Spark agent loop.
-- Plain SQL, idempotent: safe to execute twice.
--
-- agent_steps.shown_pseudonyms records, with each persisted tool
-- step, the pseudonym scope that step's structured result showed
-- the model (the pivot-granting HOST-/USER-/IP- pseudonyms from the
-- post-pseudonymization projections, never real values). A resumed
-- run rebuilds its per-run tool allowlist as the incident entities
-- UNION these persisted sets, so a pivot learned before the stop
-- stays queryable while a pseudonym that was never shown (for
-- example another incident's entity) stays refused. JSONB holding a
-- JSON array of pseudonym strings; older rows default to [].
ALTER TABLE agent_steps
    ADD COLUMN IF NOT EXISTS shown_pseudonyms JSONB NOT NULL DEFAULT '[]'::jsonb;
