-- Migration 002: core tables (Postgres is the system of record).
-- Plain SQL, idempotent: safe to execute twice. All timestamps are
-- TIMESTAMPTZ (timezone-aware UTC). Enums are TEXT + CHECK so re-runs
-- need no type juggling. updated_at columns are set by the application
-- on every write; there are deliberately no triggers.

-- Ingestion checkpoints: one row per (adapter, stream). The cursor is
-- the opaque search_after state (last_time / last_uid) as JSONB so
-- adapters can extend it without a schema change.
CREATE TABLE IF NOT EXISTS checkpoints (
    adapter TEXT NOT NULL,
    stream TEXT NOT NULL,
    cursor JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (adapter, stream)
);

-- Correlated incidents. deterministic_score / severity_floor are set
-- only by deterministic correlation. severity_id is the OCSF severity
-- (1 Informational .. 6 Fatal): it starts at the floor, a model may
-- raise it by at most one level, and it may never go below the floor;
-- human overrides come later. correlation_key is the deterministic
-- idempotency key for the cluster (entities + techniques + window):
-- re-running correlation after a crash hits the UNIQUE constraint
-- instead of creating a duplicate incident.
CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    correlation_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL DEFAULT '',
    deterministic_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    severity_floor INTEGER NOT NULL DEFAULT 1
        CHECK (severity_floor BETWEEN 1 AND 6),
    severity_id INTEGER NOT NULL DEFAULT 1
        CHECK (severity_id BETWEEN 1 AND 6),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'triaged', 'closed')),
    ai_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (ai_status IN ('pending', 'done', 'failed', 'degraded')),
    verdict TEXT,
    summary TEXT,
    response TEXT,
    language TEXT,
    entity_keys JSONB NOT NULL DEFAULT '{}'::jsonb,
    techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
    event_uids JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    CHECK (severity_id >= severity_floor AND severity_id <= severity_floor + 1)
);

-- Durable work queue (SELECT ... FOR UPDATE SKIP LOCKED). A row is
-- claimable when status is pending/failed, available_at has passed,
-- and any previous lease has expired. dedupe_key is the idempotency
-- key for enqueueing: nullable (jobs that need no dedupe leave it
-- NULL, and NULLs never collide), UNIQUE when set, so the same job
-- cannot be enqueued twice.
CREATE TABLE IF NOT EXISTS work_queue (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    dedupe_key TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'locked', 'done', 'failed', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_by TEXT,
    locked_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Learned rules. Sigma is the source format; native_text is the
-- translated SIEM rule (Wazuh XML). hits / false_positives are the
-- shadow/active counters dispositions and backtests feed.
CREATE TABLE IF NOT EXISTS rules (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    sigma_text TEXT NOT NULL,
    native_text TEXT,
    native_rule_id INTEGER
        CHECK (native_rule_id IS NULL OR native_rule_id BETWEEN 100000 AND 120000),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK (status IN ('candidate', 'shadow', 'active', 'archived', 'rolled_back')),
    lineage JSONB NOT NULL DEFAULT '{}'::jsonb,
    ttl INTERVAL,
    hits INTEGER NOT NULL DEFAULT 0 CHECK (hits >= 0),
    false_positives INTEGER NOT NULL DEFAULT 0 CHECK (false_positives >= 0),
    incident_id BIGINT REFERENCES incidents (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deployed_at TIMESTAMPTZ
);

-- Persisted Spark agent steps, in order, for the live UI trace and
-- for resuming after a stop.
CREATE TABLE IF NOT EXISTS agent_steps (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL CHECK (step_number >= 1),
    tool TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_summary TEXT,
    tokens INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (incident_id, step_number)
);

-- Analyst dispositions: exactly one of incident / rule per row.
-- ON DELETE RESTRICT: analyst verdicts are never deleted silently
-- with their incident or rule; removal must delete them explicitly.
CREATE TABLE IF NOT EXISTS dispositions (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT REFERENCES incidents (id) ON DELETE RESTRICT,
    rule_id BIGINT REFERENCES rules (id) ON DELETE RESTRICT,
    verdict TEXT NOT NULL
        CHECK (verdict IN ('tp', 'fp', 'benign_authorized')),
    analyst TEXT NOT NULL,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((incident_id IS NOT NULL) <> (rule_id IS NOT NULL))
);

-- Deployment-stable pseudonyms: the same (entity_kind, entity_value)
-- always maps to the same pseudonym across incidents, and the UI maps
-- pseudonym -> entity_value back for the analyst. Real values in this
-- table never leave the on-prem deployment.
CREATE TABLE IF NOT EXISTS pseudonyms (
    id BIGSERIAL PRIMARY KEY,
    entity_kind TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    pseudonym TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (entity_kind, entity_value),
    UNIQUE (pseudonym)
);

-- Model spend ledger: one row per billed call.
CREATE TABLE IF NOT EXISTS spend (
    id BIGSERIAL PRIMARY KEY,
    model TEXT NOT NULL,
    tokens_in INTEGER NOT NULL DEFAULT 0 CHECK (tokens_in >= 0),
    tokens_out INTEGER NOT NULL DEFAULT 0 CHECK (tokens_out >= 0),
    usd NUMERIC(12, 6) NOT NULL DEFAULT 0 CHECK (usd >= 0),
    incident_id BIGINT REFERENCES incidents (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Every LLM attempt (corvus/llm/call.py): validators run in order and
-- the failed one is named; token split is exact (prompt / cached /
-- reasoning / answer / overhead). Security failures are never retried.
CREATE TABLE IF NOT EXISTS llm_attempts (
    id BIGSERIAL PRIMARY KEY,
    call_id TEXT NOT NULL,
    incident_id BIGINT REFERENCES incidents (id) ON DELETE SET NULL,
    model TEXT NOT NULL,
    purpose TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    failed_validator TEXT,
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    prompt_tokens INTEGER NOT NULL DEFAULT 0 CHECK (prompt_tokens >= 0),
    cached_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
    reasoning_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reasoning_tokens >= 0),
    answer_tokens INTEGER NOT NULL DEFAULT 0 CHECK (answer_tokens >= 0),
    overhead_tokens INTEGER NOT NULL DEFAULT 0 CHECK (overhead_tokens >= 0),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    outcome TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Queue: claim order (available_at, id) over claimable rows only, and
-- lease reclaim by expiry. The partial indexes keep the hot claim
-- query off done/dead rows.
CREATE INDEX IF NOT EXISTS idx_work_queue_claim
    ON work_queue (available_at, id)
    WHERE status IN ('pending', 'failed');
CREATE INDEX IF NOT EXISTS idx_work_queue_lease
    ON work_queue (lease_expires_at)
    WHERE locked_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_work_queue_kind_status
    ON work_queue (kind, status, available_at);

-- Incident list: server-side pagination ordered newest first, with
-- the status / ai_status / severity filters the UI offers.
CREATE INDEX IF NOT EXISTS idx_incidents_list
    ON incidents (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status_list
    ON incidents (status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_ai_status_list
    ON incidents (ai_status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity_list
    ON incidents (severity_floor DESC, deterministic_score DESC, created_at DESC, id DESC);

-- Foreign-key and lookup indexes. (pseudonyms.pseudonym needs no
-- extra index: its UNIQUE constraint already creates one.)
CREATE INDEX IF NOT EXISTS idx_agent_steps_incident
    ON agent_steps (incident_id, step_number);
CREATE INDEX IF NOT EXISTS idx_dispositions_incident
    ON dispositions (incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dispositions_rule
    ON dispositions (rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rules_status
    ON rules (status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_rules_incident
    ON rules (incident_id);
CREATE INDEX IF NOT EXISTS idx_spend_model_time
    ON spend (model, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_spend_created_at
    ON spend (created_at);
CREATE INDEX IF NOT EXISTS idx_spend_incident
    ON spend (incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_llm_attempts_call
    ON llm_attempts (call_id, attempt_number);
CREATE INDEX IF NOT EXISTS idx_llm_attempts_incident
    ON llm_attempts (incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_llm_attempts_model_time
    ON llm_attempts (model, created_at DESC);
