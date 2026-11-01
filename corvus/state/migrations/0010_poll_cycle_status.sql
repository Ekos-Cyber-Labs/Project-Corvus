-- Migration 010: close live-poll cycle rows on failure and track skew.
-- Plain SQL, idempotent: safe to execute twice. All timestamps are
-- TIMESTAMPTZ (timezone-aware UTC).
--
-- A cycle that raises after its row was opened must still close the
-- row (completed_at NOT NULL) with status 'failed' and the exception
-- class, or the ledger shows an open row forever while the retry
-- re-reads the same window. status defaults to 'ok' so older rows
-- read as successes; error_class carries type(exc).__name__ on
-- failure and '' on success. future_dated counts alerts skipped for
-- arriving more than 10 minutes ahead of the poll clock (they never
-- advance the checkpoint).

ALTER TABLE wazuh_poll_cycles
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ok'
        CHECK (status IN ('ok', 'failed'));
ALTER TABLE wazuh_poll_cycles
    ADD COLUMN IF NOT EXISTS error_class TEXT NOT NULL DEFAULT '';
ALTER TABLE wazuh_poll_cycles
    ADD COLUMN IF NOT EXISTS future_dated INTEGER NOT NULL DEFAULT 0
        CHECK (future_dated >= 0);
