-- One GitHub token per org, for the new GITHUB_SECRET_SEARCH check (searches public GitHub
-- code for the target's own domain, then re-checks any hit with the existing
-- SecretPatternScanner). Unlike slack_integrations' webhook_url (plaintext - a revocable,
-- limited-blast-radius secret), encrypted_token is AES-256-GCM ciphertext via
-- SecretCredentialCipher: a GitHub personal access token is a materially more sensitive,
-- reusable-against-a-third-party credential, and this codebase's own house rule (see
-- V51__sso_handoff_no_plaintext_tokens.sql) is that a real, usable credential never sits in
-- plaintext at rest. One-way hashing (as refresh_tokens/worker_credentials already use)
-- doesn't apply here - the token must be recovered in full to actually call GitHub's API.
CREATE TABLE github_secret_search_integrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    encrypted_token bytea NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
