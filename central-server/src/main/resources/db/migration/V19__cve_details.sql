-- Global cache of human-readable CVE descriptions, sourced from osv.dev.
-- Keyed only on cve_id (not technology/version like cve_lookup_cache) -
-- a CVE's description doesn't vary by which of your targets happens to be
-- running the affected version, so this is naturally shared and deduplicated
-- across every technology/target that references the same CVE.
CREATE TABLE cve_details (
    cve_id         text PRIMARY KEY,
    description    text,
    severity       text,
    published_date timestamptz,
    source         text NOT NULL,
    fetched_at     timestamptz NOT NULL DEFAULT now()
);
