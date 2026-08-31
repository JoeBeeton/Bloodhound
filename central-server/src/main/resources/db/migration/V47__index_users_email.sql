-- A performance review found UserRepository#findLocalActiveByEmail's query - the local-login
-- lookup, run on every single login attempt - had no supporting index at all. The only existing
-- index touching email is the composite uq_users_org_email UNIQUE (organization_id, email) from
-- V1__init.sql, which Postgres can't use for an email-only filter (leftmost-column rule);
-- confirmed live via EXPLAIN against the running database: a plain Seq Scan on users. Every other
-- hash-lookup table in this schema (refresh_tokens.token_hash, api_keys.key_hash,
-- scim_tokens.token_hash, worker_credentials.api_key_hash) already has its own dedicated index -
-- this was the one missed.
--
-- Partial (WHERE identity_source = 'LOCAL' AND status = 'ACTIVE'), matching the query's own WHERE
-- clause exactly, and NOT unique: email is only unique per-organization (see
-- uq_users_org_email above, and findLocalActiveByEmail's own javadoc) - two different orgs' LOCAL
-- users can legitimately share an email address, so a plain unique index on email alone would
-- incorrectly enforce a global-uniqueness guarantee this app's data model does not make.
CREATE INDEX idx_users_email_local_active ON users (email)
    WHERE identity_source = 'LOCAL' AND status = 'ACTIVE';
