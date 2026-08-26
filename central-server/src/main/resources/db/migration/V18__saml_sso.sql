-- SAML SSO: per-organization IdP configuration, activating the identity_source
-- seam reserved on `users` since V1. One SAML IdP per org for this version -
-- simplest reasonable scope, matches how most orgs actually operate (one
-- corporate IdP), and avoids building IdP-selection UX nobody's asked for yet.
CREATE TABLE identity_providers (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id               UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    -- URL-path-safe slug used literally in Spring Security's per-registration
    -- SAML endpoint paths (/saml2/authenticate/{registration_id} etc). Reuses
    -- the org's own slug rather than generating a separate one - already
    -- unique and already URL-safe.
    registration_id               TEXT NOT NULL UNIQUE,
    idp_entity_id                 TEXT NOT NULL,
    idp_sso_url                   TEXT NOT NULL,
    idp_x509_cert                 TEXT NOT NULL,
    -- Real IdPs vary in which SAML assertion attribute carries email/name -
    -- admin-configurable per org rather than a single hardcoded guess.
    email_attribute_name          TEXT NOT NULL DEFAULT 'email',
    display_name_attribute_name   TEXT,
    enabled                       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Short-lived, single-use handoff so a successful SAML login (a browser
-- redirect chain) never puts a real access/refresh token in a URL - only
-- this opaque code crosses the browser, and webui's backend exchanges it
-- server-side for the real tokens (see auth.sso.SsoHandoffCodeRepository).
-- Deleted on consumption (not just marked) so the actual token values never
-- sit at rest longer than necessary; a consumed or expired code is simply
-- absent, not distinguishable from a forged one.
CREATE TABLE sso_handoff_codes (
    code           TEXT PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token   TEXT NOT NULL,
    expires_in     BIGINT NOT NULL,
    refresh_token  TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
