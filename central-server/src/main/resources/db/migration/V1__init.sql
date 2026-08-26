-- Milestone 0: identity/tenancy backbone only. Targets, scan_jobs, findings,
-- score_snapshots etc. land in later migrations (Milestones 1-5).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    plan_tier   TEXT NOT NULL DEFAULT 'free',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- identity_source: LOCAL for Phase 1 username/password users. SAML/SCIM are
-- reserved values so Phase 2 can slot in without a schema rewrite: a
-- SAML/SCIM-provisioned user row has password_hash NULL and identity_source
-- != 'LOCAL'; Spring Security picks the AuthenticationProvider by that column.
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    password_hash   TEXT,
    password_algo   TEXT NOT NULL DEFAULT 'bcrypt',
    identity_source TEXT NOT NULL DEFAULT 'LOCAL'
        CHECK (identity_source IN ('LOCAL', 'SAML', 'SCIM')),
    external_id     TEXT,
    role            TEXT NOT NULL DEFAULT 'VIEWER'
        CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
    status          TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'DISABLED', 'PENDING_PROVISION')),
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_org_email UNIQUE (organization_id, email),
    CONSTRAINT uq_users_org_identity_source_external_id
        UNIQUE (organization_id, identity_source, external_id)
);

CREATE INDEX idx_users_organization_id ON users(organization_id);
