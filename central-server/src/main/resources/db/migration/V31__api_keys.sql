-- Read-only external API keys, one org+creator per key. Mirrors scim_tokens'/
-- worker_credentials' hash-at-rest pattern - only a SHA-256 hash is stored,
-- never the raw key. key_prefix stores the first ~12 characters of the raw
-- key (before hashing) purely for display ("bhk_xY9fA2Bq...") so a user can
-- tell their keys apart in a list without the full secret ever being
-- retrievable again after creation.
--
-- expires_at is NOT NULL by design: unlike a user's login session, an API
-- key is a long-lived bearer credential handed to external tooling, so this
-- app never issues one without a bounded lifetime (see ApiKeyController -
-- the create request accepts a caller-chosen expiry, capped server-side).
CREATE TABLE api_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label text NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz
);

CREATE UNIQUE INDEX idx_api_keys_hash ON api_keys (key_hash);
CREATE INDEX idx_api_keys_created_by ON api_keys (created_by_user_id);
CREATE INDEX idx_api_keys_org ON api_keys (organization_id);
