-- Migration 011: per-step tool-result emitted pseudonyms for the analysis loop.
--
-- agent_steps.shown_pseudonyms (migration 0006) records the
-- pivot-granting pseudonyms of a step's structured result (typed
-- fields only) and rebuilds the tool allowlist. This column records,
-- with each persisted tool step, the pseudonyms the pseudonymizer
-- actually substituted into that step's model-bound payload
-- (``prepare_payload``'s own substitution report, including free-text
-- matches of registered values in no typed field). The verdict scope
-- unions them; the allowlist never grows from them, so a resumed run
-- rebuilds the same citation scope without granting new pivoting
-- rights. JSONB holding a JSON array of pseudonym strings; older
-- rows default to [].
ALTER TABLE agent_steps
    ADD COLUMN IF NOT EXISTS emitted_pseudonyms JSONB NOT NULL DEFAULT '[]'::jsonb;
