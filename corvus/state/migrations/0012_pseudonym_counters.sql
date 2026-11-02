-- Migration 012: monotonic per-kind pseudonym counters.
--
-- Pseudonym numbers used to come from max(existing number for the
-- kind) + 1, so deleting the highest rows (for example via
-- purge_file_pseudonyms) handed the same HOST-/DOMAIN- numbers to
-- later entities and an old artifact could then reveal a different
-- entity. Numbers now come from a monotonic per-kind counter that
-- only advances: deleting rows never reuses a number. The table is
-- seeded from the current table maximum, so pre-migration rows keep
-- their numbers and no new row collides with them. Allocation and
-- purging both run under the same ``corvus:pseudonyms`` advisory
-- lock, so a concurrent run cannot interleave between the purge's
-- reference check and its delete.
CREATE TABLE IF NOT EXISTS pseudonym_counters (
    entity_kind TEXT PRIMARY KEY,
    next_number BIGINT NOT NULL CHECK (next_number >= 1)
);

INSERT INTO pseudonym_counters (entity_kind, next_number)
SELECT
    entity_kind,
    COALESCE(
        MAX(
            CAST(
                NULLIF(regexp_replace(pseudonym, '^[A-Z]+-', ''), '')
                AS INTEGER
            )
        ),
        0
    ) + 1
FROM pseudonyms
GROUP BY entity_kind
ON CONFLICT (entity_kind) DO NOTHING;
