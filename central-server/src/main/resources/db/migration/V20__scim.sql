-- SCIM 2.0 bearer tokens, one org per token. Mirrors worker_credentials'
-- hash-at-rest pattern (see auth.WorkerCredentialRepository) rather than
-- storing the raw token.
CREATE TABLE scim_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    label text NOT NULL,
    token_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE UNIQUE INDEX idx_scim_tokens_hash ON scim_tokens (token_hash);
CREATE INDEX idx_scim_tokens_org ON scim_tokens (organization_id);
