-- Tier 2 cloud-storage bucket brute-force discovery (BUCKET_BRUTE_FORCE) -
-- guesses bucket names related to a target's own brand across five
-- S3-API-compatible providers (AWS S3, GCS, DigitalOcean Spaces, Linode,
-- Scaleway), gated behind the same authorization_status = 'AUTHORIZED'
-- attestation as PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN. Distinct
-- rule_id from the existing CNAME-based EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING
-- (see V25) - a guessed match is a different provenance/confidence claim
-- than "your own DNS points here", even though the underlying risk (public
-- data exposure) is identical.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC', 'EXPOSURE', 'CRITICAL',
 'Publicly listable cloud storage bucket (discovered via brand-name guessing)',
 'A cloud storage bucket whose name is related to this organization''s brand - discovered by guessing common bucket-naming conventions against its root domain, not via any of the target''s own DNS records - allows anyone to list its full contents without authentication. Because this bucket was found by name-guessing rather than a DNS reference the target actually controls, ownership should be confirmed before remediation (a similarly-named bucket can occasionally belong to an unrelated third party).',
 'If the bucket belongs to your organization: disable public directory listing (S3: remove public "List objects" grants/bucket policy; GCS: remove allUsers/allAuthenticatedUsers from the bucket''s IAM policy; equivalent for DigitalOcean Spaces/Linode/Scaleway). If it does not belong to your organization, no action is needed - this is a coincidental name match.',
 2.0);

-- Tracks every (target, candidate bucket name, provider) combination the
-- BUCKET_BRUTE_FORCE module has ever checked, upserted on every run - so a
-- re-run of a deep scan skips names already checked recently (see
-- ScanRunService's cooldown-windowed exclusion query) instead of re-issuing
-- the same few hundred requests against AWS/GCS/etc. every time, while still
-- eventually re-checking (a bucket can be created or made public later).
-- Current-state-per-candidate, not append-only history - same shape as
-- typosquat_candidates (V15): a candidate's listability is a live fact, not
-- something worth keeping a full timeline of.
CREATE TABLE bucket_brute_force_checks (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id        UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    candidate_name   TEXT NOT NULL,
    provider         TEXT NOT NULL,
    first_checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    was_listable     BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (target_id, candidate_name, provider)
);

CREATE INDEX idx_bucket_brute_force_checks_target ON bucket_brute_force_checks (target_id);
