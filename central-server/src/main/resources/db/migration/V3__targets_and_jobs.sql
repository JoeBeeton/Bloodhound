-- Milestone 2: targets to track, the Postgres-backed scan job queue, and
-- worker API-key credentials.

CREATE TABLE targets (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname              TEXT NOT NULL,
    target_type           TEXT NOT NULL CHECK (target_type IN ('OWN', 'COMPETITOR', 'WATCHLIST')),
    -- Nothing enforces this yet - it's the seam Phase 2's Tier 2 (deep
    -- port scan/ZAP) scanning gates on. Deep-scan job creation will just add
    -- "WHERE targets.authorization_status = 'AUTHORIZED'" - no migration needed.
    authorization_status  TEXT NOT NULL DEFAULT 'UNAUTHORIZED'
        CHECK (authorization_status IN ('UNAUTHORIZED', 'AUTHORIZED')),
    -- A plain seconds count rather than Postgres INTERVAL - the scheduler
    -- only ever needs to add it to "now()"; INTERVAL's JDBC mapping (PGInterval)
    -- buys nothing here and complicates every repository method that touches it.
    scan_cadence_seconds  INTEGER NOT NULL DEFAULT 86400,
    next_scan_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_targets_org_hostname UNIQUE (organization_id, hostname)
);

CREATE INDEX idx_targets_organization_id ON targets(organization_id);

-- Attestation record for a target being cleared for Tier 2 active scanning.
-- Stored now (Phase 1), enforced later (Phase 2) - see authorization_status
-- above. No endpoint creates these yet; the table exists so Phase 2 doesn't
-- need a migration to add it.
CREATE TABLE target_authorizations (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id              UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    authorized_by_user_id  UUID NOT NULL REFERENCES users(id),
    authorized_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    attestation_text       TEXT NOT NULL,
    revoked_at             TIMESTAMPTZ,
    revoked_by_user_id     UUID REFERENCES users(id)
);

CREATE INDEX idx_target_authorizations_target_id ON target_authorizations(target_id);

-- Groups all scan_jobs for one scan cycle of a target - the unit the
-- (Milestone 5) scoring engine will operate on.
CREATE TABLE scan_runs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id             UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    triggered_by          TEXT NOT NULL CHECK (triggered_by IN ('SCHEDULED', 'MANUAL')),
    triggered_by_user_id  UUID REFERENCES users(id),
    started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at          TIMESTAMPTZ,
    status                TEXT NOT NULL DEFAULT 'RUNNING'
        CHECK (status IN ('RUNNING', 'COMPLETE', 'PARTIAL_FAILURE'))
);

CREATE INDEX idx_scan_runs_target_id ON scan_runs(target_id);

-- The Postgres-backed job queue. Workers never run SQL themselves - they
-- POST /api/v1/jobs/claim and central-server does the
-- "SELECT ... FOR UPDATE SKIP LOCKED" claim on their behalf (see
-- JobClaimService), which is what keeps workers DB-credential-free.
CREATE TABLE scan_jobs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id       UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    target_id         UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_type       TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CLAIMED', 'RUNNING', 'COMPLETE', 'FAILED', 'CANCELLED')),
    priority          SMALLINT NOT NULL DEFAULT 0,
    run_after         TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_by        TEXT,
    claimed_at        TIMESTAMPTZ,
    lease_expires_at  TIMESTAMPTZ,
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    max_attempts      INTEGER NOT NULL DEFAULT 3,
    payload           JSONB NOT NULL DEFAULT '{}',
    -- Milestone 2's NOOP module has nothing structured to report; the real
    -- findings table + ingestion pipeline lands in Milestone 3. Until then,
    -- a job's raw result is just kept alongside it.
    result_metadata   JSONB,
    error_detail      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_jobs_claimable ON scan_jobs(status, run_after);
CREATE INDEX idx_scan_jobs_scan_run_id ON scan_jobs(scan_run_id);
CREATE INDEX idx_scan_jobs_claimed_by ON scan_jobs(claimed_by);

-- Worker service credentials - a separate auth mechanism from user JWTs (see
-- WorkerApiKeyAuthFilter). Seeded from the WORKER_API_KEY env var at startup
-- by WorkerCredentialBootstrapRunner.
CREATE TABLE worker_credentials (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label         TEXT NOT NULL,
    api_key_hash  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_worker_credentials_api_key_hash ON worker_credentials(api_key_hash);
