-- CVE / CISA KEV correlation over fingerprinted technology versions.
--
-- kev_catalog mirrors CISA's Known Exploited Vulnerabilities feed (a free,
-- no-auth, CDN-served static JSON file, ~1600 entries) - refreshed wholesale
-- roughly daily, cheap to store in full since it's small and a CVE appearing
-- here (confirmed active exploitation in the wild) is a materially stronger
-- signal than a bare CVSS score.
--
-- cve_lookup_cache is a shared-across-ALL-targets cache of NVD lookup
-- results keyed by (technology, version) - not per-target, since many
-- different scanned hosts commonly run the same nginx/WordPress/PHP/Apache
-- version, so this keeps real NVD call volume low despite NVD's
-- ~5-requests-per-30s unauthenticated rate limit (see
-- VulnerabilityCorrelationScheduler for the rate-limited refresh logic).
CREATE TABLE kev_catalog (
    cve_id              TEXT PRIMARY KEY,
    vendor_project      TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          DATE,
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cve_lookup_cache (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technology_name   TEXT NOT NULL,
    version           TEXT NOT NULL,
    cve_ids           JSONB NOT NULL DEFAULT '[]'::jsonb,
    kev_matches       JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_severity      TEXT,
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (technology_name, version)
);

-- CVE_CORRELATION: a per-target scan_run (one CVE_CORRELATION scan_job,
-- created already-COMPLETE - the NVD/KEV lookups themselves happen once,
-- shared across targets, in cve_lookup_cache, not per-target) created by
-- VulnerabilityCorrelationScheduler whenever a target's fingerprinted tech
-- has a newly-cached CVE/KEV match, purely so the resulting findings go
-- through the normal ResultIngestionService/scan_run machinery (first-seen
-- tracking, scoring) like every other finding in this system, and don't need
-- a bespoke insert path. Same "lightweight synthetic run" pattern CT_CHECK
-- established.
ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_triggered_by_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_triggered_by_check
    CHECK (triggered_by IN ('SCHEDULED', 'MANUAL', 'CT_CHECK', 'CT_TRIGGERED', 'CVE_CORRELATION'));

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('TECH_KNOWN_EXPLOITED_VULNERABILITY', 'EXPOSURE', 'CRITICAL',
 'Actively exploited vulnerability in detected software',
 'The fingerprinted technology and version running on this host has at least one CVE listed in CISA''s Known Exploited Vulnerabilities (KEV) catalog, meaning it is confirmed to be under active exploitation in the wild - not just theoretically vulnerable.',
 'Patch or upgrade the affected software immediately. KEV entries carry CISA-recommended remediation deadlines for federal agencies and represent the highest-confidence exploitation signal available from public data.',
 1.5),
('TECH_KNOWN_CVE', 'EXPOSURE', 'MEDIUM',
 'Known CVE in detected software version',
 'The fingerprinted technology and version running on this host has one or more published CVEs in the National Vulnerability Database. Reported severity is derived from the highest CVSS base score found among them.',
 'Review the referenced CVE(s) and apply the vendor-recommended patch or upgrade. Not every listed CVE is necessarily exploitable in your specific configuration - use this as a prioritization signal alongside other findings, not a certainty.',
 1.0);
