-- Migration 009: one row per (Sigma id, version) of a learned rule.
-- Plain SQL, idempotent: safe to execute twice. The Sigma id lives in
-- lineage (see corvus/learning/rules.py), so the unique index is on the
-- extracted text plus the version column: a second row reusing one
-- Sigma id at an already-stored version is refused by the database,
-- backing the store's latest-revision check against racers.
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_sigma_id_version
    ON rules (((lineage ->> 'sigma_rule_id')), version);
