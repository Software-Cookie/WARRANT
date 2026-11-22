-- Warrant control plane — core schema (Project Bible §13.2).
-- The application connects through the warrant_app role. Every tenant table is under
-- row-level security bound to the transaction-local setting warrant.tenant; a query that
-- forgets to filter by tenant returns nothing rather than everything.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warrant_app') THEN
        CREATE ROLE warrant_app NOLOGIN;
    END IF;
END
$$;

-- tenants ---------------------------------------------------------------------
CREATE TABLE tenants (
    id                      TEXT PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name                    TEXT NOT NULL,
    region                  TEXT NOT NULL,
    kms_key_uri             TEXT NOT NULL,
    idp_issuer              TEXT,
    fail_mode               TEXT NOT NULL DEFAULT 'closed' CHECK (fail_mode IN ('closed', 'open_read')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    kms_audit_key_uri       TEXT NOT NULL DEFAULT '',
    active_policy_v         TEXT,
    escalation_ttl_seconds  INTEGER NOT NULL DEFAULT 900 CHECK (escalation_ttl_seconds BETWEEN 30 AND 86400),
    max_warrant_ttl_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (max_warrant_ttl_seconds BETWEEN 60 AND 604800),
    max_ceiling_rows        BIGINT NOT NULL DEFAULT 100000 CHECK (max_ceiling_rows >= 0),
    max_hops                SMALLINT NOT NULL DEFAULT 5 CHECK (max_hops BETWEEN 0 AND 16),
    arg_retention_days      INTEGER NOT NULL DEFAULT 0 CHECK (arg_retention_days BETWEEN 0 AND 365),
    settings                JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- policy, versioned and immutable once published ------------------------------
CREATE TABLE policies (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    version      TEXT NOT NULL,
    source       TEXT NOT NULL,
    compiled     JSONB NOT NULL,
    published_at TIMESTAMPTZ,
    published_by TEXT,
    PRIMARY KEY (tenant_id, version)
);

-- warrants ---------------------------------------------------------------------
CREATE TABLE warrants (
    wid        TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    principal  TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    mandate    TEXT NOT NULL,
    scope      TEXT[] NOT NULL,
    ceiling    JSONB NOT NULL,
    parent_wid TEXT REFERENCES warrants(wid),
    hops_left  SMALLINT NOT NULL,
    policy_v   TEXT NOT NULL,
    issued_at  TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    digest     TEXT NOT NULL,
    kid        TEXT NOT NULL,
    chain      TEXT NOT NULL,
    revoke_reason TEXT
);
CREATE INDEX ON warrants (tenant_id, principal, issued_at DESC);
CREATE INDEX ON warrants (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX warrants_revoked_idx ON warrants (tenant_id, revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX warrants_parent_idx ON warrants (parent_wid);

-- audit chain: append-only, one chain per tenant -------------------------------
CREATE TABLE audit_entries (
    tenant_id    TEXT NOT NULL,
    idx          BIGINT NOT NULL,
    prev_digest  TEXT NOT NULL,
    entry_digest TEXT NOT NULL,
    wid          TEXT NOT NULL,
    principal    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    tool_id      TEXT NOT NULL,
    verb         TEXT NOT NULL,
    target       TEXT NOT NULL,
    arg_digest   TEXT NOT NULL,
    arg_ref      TEXT,
    verdict      TEXT NOT NULL,
    reason_code  TEXT NOT NULL,
    policy_v     TEXT NOT NULL,
    model_v      TEXT,
    stage        TEXT NOT NULL,
    approver     TEXT,
    latency_ms   INTEGER NOT NULL,
    decided_at   TIMESTAMPTZ NOT NULL,
    signature    TEXT,
    PRIMARY KEY (tenant_id, idx)
);
-- The bible writes this as "FROM ALL"; PostgreSQL spells it PUBLIC. No application role
-- ever receives UPDATE, DELETE or TRUNCATE on the chain.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_entries FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_entries FROM warrant_app;
CREATE INDEX audit_entries_trace_idx ON audit_entries (tenant_id, target, verb, decided_at);
CREATE INDEX audit_entries_principal_idx ON audit_entries (tenant_id, principal, decided_at);

-- Defence in depth: even the table owner cannot rewrite history through normal SQL.
CREATE FUNCTION audit_entries_append_only() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'audit_entries is append-only (attempted %)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE OR DELETE ON audit_entries
    FOR EACH ROW EXECUTE FUNCTION audit_entries_append_only();
CREATE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON audit_entries
    FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only();

CREATE TABLE chain_heads (
    tenant_id       TEXT PRIMARY KEY REFERENCES tenants(id),
    last_idx        BIGINT NOT NULL,
    last_digest     TEXT NOT NULL,
    last_signed_idx BIGINT NOT NULL DEFAULT 0,
    last_signed_at  TIMESTAMPTZ
);

CREATE TABLE audit_ingest (
    tenant_id TEXT NOT NULL,
    event_key TEXT NOT NULL,
    idx       BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, event_key)
);

-- parked escalations ------------------------------------------------------------
CREATE TABLE escalations (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    wid                TEXT NOT NULL,
    request            JSONB NOT NULL,
    card               JSONB NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'partial', 'timeout', 'coalesced')),
    approver           TEXT,
    decided_at         TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ NOT NULL,
    version            INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason_code        TEXT NOT NULL,
    severity           TEXT NOT NULL CHECK (severity IN ('high', 'medium')),
    coalesce_key       TEXT NOT NULL,
    coalesced_into     TEXT REFERENCES escalations(id),
    arguments_enc      BYTEA NOT NULL,
    alternative_enc    BYTEA,
    applied_scope      TEXT[],
    warrant_chain      TEXT NOT NULL,
    stage              TEXT NOT NULL,
    policy_v           TEXT NOT NULL,
    model_v            TEXT,
    release_state      TEXT NOT NULL DEFAULT 'none'
                        CHECK (release_state IN ('none', 'ready', 'claimed', 'released', 'failed')),
    release_claimed_by TEXT,
    release_claimed_at TIMESTAMPTZ,
    result_status      INTEGER,
    result_enc         BYTEA,
    released_at        TIMESTAMPTZ,
    delivery           JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ON escalations (tenant_id, state, expires_at);
CREATE INDEX escalations_coalesce_idx ON escalations (tenant_id, coalesce_key, state);
CREATE INDEX escalations_release_idx ON escalations (tenant_id, release_state);

-- registry, identity, approvers ------------------------------------------------
CREATE TABLE agents (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    name          TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    build_hash    TEXT NOT NULL CHECK (build_hash ~ '^sha256:[0-9a-f]{64}$'),
    allowed_scope TEXT[] NOT NULL,
    owner         TEXT NOT NULL,
    suspended_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE tools (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    tool_id    TEXT NOT NULL,
    definition JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id, tool_id)
);

CREATE TABLE console_users (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    email      TEXT NOT NULL,
    roles      TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, email),
    CHECK (NOT ('auditor' = ANY (roles) AND 'approver' = ANY (roles)))
);

CREATE TABLE approvers (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    email     TEXT NOT NULL,
    channels  TEXT[] NOT NULL DEFAULT ARRAY['console'],
    groups    TEXT[] NOT NULL DEFAULT ARRAY['default'],
    PRIMARY KEY (tenant_id, email)
);

CREATE TABLE key_metadata (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    kid        TEXT NOT NULL,
    purpose    TEXT NOT NULL CHECK (purpose IN ('warrant', 'audit')),
    algorithm  TEXT NOT NULL,
    public_pem TEXT NOT NULL,
    source     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, kid)
);

CREATE TABLE admin_change_requests (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    change       JSONB NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by  TEXT,
    approved_at  TIMESTAMPTZ,
    CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

-- analytics: not the legal record, feeds dashboards and policy replay ---------
CREATE TABLE decision_events (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    decided_at    TIMESTAMPTZ NOT NULL,
    wid           TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    principal     TEXT NOT NULL,
    tool_id       TEXT NOT NULL,
    verb          TEXT NOT NULL,
    target        TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    reason_code   TEXT,
    stage         TEXT NOT NULL,
    latency_ms    INTEGER NOT NULL,
    policy_v      TEXT NOT NULL,
    model_v       TEXT,
    escalation_id TEXT,
    approver      TEXT,
    explanation   TEXT,
    rows_affected BIGINT,
    facts         JSONB NOT NULL,
    chain_idx     BIGINT
);
CREATE INDEX decision_events_time_idx ON decision_events (tenant_id, decided_at DESC);
CREATE INDEX decision_events_id_idx ON decision_events (tenant_id, id);

-- row-level security ------------------------------------------------------------
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['policies', 'warrants', 'audit_entries', 'chain_heads', 'audit_ingest', 'escalations',
                             'agents', 'tools', 'approvers', 'key_metadata', 'admin_change_requests',
                             'decision_events']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''warrant.tenant'', true)) '
                       'WITH CHECK (tenant_id = current_setting(''warrant.tenant'', true))', t);
    END LOOP;
END
$$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = current_setting('warrant.tenant', true))
    WITH CHECK (id = current_setting('warrant.tenant', true));
-- Explicit, transaction-scoped system reads: listing tenants for background jobs.
CREATE POLICY system_list ON tenants FOR SELECT
    USING (current_setting('warrant.system', true) = 'on');

ALTER TABLE console_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE console_users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON console_users
    USING (tenant_id = current_setting('warrant.tenant', true))
    WITH CHECK (tenant_id = current_setting('warrant.tenant', true));
CREATE POLICY system_lookup ON console_users FOR SELECT
    USING (current_setting('warrant.system', true) = 'on');

-- grants ------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO warrant_app;
GRANT SELECT, INSERT, UPDATE ON tenants, policies, warrants, chain_heads, escalations, agents, tools,
    console_users, approvers, key_metadata, admin_change_requests TO warrant_app;
GRANT SELECT, INSERT ON audit_entries, audit_ingest, decision_events TO warrant_app;
GRANT DELETE ON approvers, console_users TO warrant_app;
GRANT USAGE, SELECT ON SEQUENCE decision_events_id_seq TO warrant_app;
