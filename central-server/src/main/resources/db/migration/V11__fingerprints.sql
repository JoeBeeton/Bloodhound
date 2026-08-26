-- Passive technology-stack and hosting-provider fingerprinting, per hostname
-- (the target's own root domain plus its discovered subdomains). A
-- current-state snapshot, not a history table like whois_records: which CDN
-- or CMS a site runs on today isn't a security signal worth historizing the
-- way a registrar change is, so each scan simply overwrites the prior row.
CREATE TABLE fingerprints (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id         UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    hostname          TEXT NOT NULL,
    technologies      JSONB NOT NULL DEFAULT '[]'::jsonb,
    hosting_provider  TEXT,
    hosting_asn       TEXT,
    -- Raw ASN organization string from the Cymru lookup, kept alongside the
    -- friendly hosting_provider mapping so the underlying data is still
    -- visible/auditable when the curated provider-name table doesn't
    -- recognize a smaller or unusual host.
    hosting_asn_org   TEXT,
    captured_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, hostname)
);

CREATE INDEX idx_fingerprints_target ON fingerprints(target_id);
