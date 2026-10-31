-- Migration 007: unique native rule ids (no reuse across the lifecycle).
-- Plain SQL, idempotent: safe to execute twice. The partial index
-- refuses a second row carrying an allocated native_rule_id while
-- rows without one (candidates not yet deployed) never collide.
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_native_rule_id
    ON rules (native_rule_id)
    WHERE native_rule_id IS NOT NULL;
