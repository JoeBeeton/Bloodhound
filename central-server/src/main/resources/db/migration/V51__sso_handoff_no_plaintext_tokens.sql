-- A security review found this table stored raw, unhashed access and refresh tokens - unlike
-- refresh_tokens (SHA-256 hashed at rest) and api_keys/scim_tokens/worker credentials (same),
-- this was the one place in the whole app minting real, usable, up-to-90-day credentials into
-- plaintext at rest. Tokens are now minted only at exchange time (SsoExchangeController), not
-- ahead of time and stored here - this table holds only the opaque code and which user it's for,
-- the same "handle, not the real thing" shape every other credential-adjacent table in this app
-- already uses. Dropping these columns also destroys any plaintext tokens already sitting in
-- existing rows, not just stopping new ones from being written.
ALTER TABLE sso_handoff_codes
    DROP COLUMN access_token,
    DROP COLUMN expires_in,
    DROP COLUMN refresh_token;
