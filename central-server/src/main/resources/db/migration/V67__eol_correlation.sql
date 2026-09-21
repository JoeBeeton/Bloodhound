-- End-of-life software detection over fingerprinted technology versions. A close
-- structural twin of V13__cve_kev_correlation.sql's CVE/KEV correlation - see
-- EolCorrelationScheduler's own javadoc for the full design. Different signal from CVE
-- correlation: a known CVE affects a specific version; EOL status means the version gets
-- no future patches at all, even for CVEs not yet discovered.
--
-- eol_release_cache mirrors one product's full release-cycle list from endoflife.date's
-- API (one call per product covers every cycle at once, unlike NVD's per-version
-- lookup) - small per-product row count, replaced wholesale on each refresh.
--
-- eol_product_fetch_state tracks "have we asked about this product recently"
-- independently of eol_release_cache's row count: a product whose fetch legitimately
-- came back empty (a 404) would otherwise look identical to "never fetched" and get
-- re-queried every tick forever instead of respecting the stale-after window.
CREATE TABLE eol_release_cache (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technology_name          TEXT NOT NULL,
    release_cycle            TEXT NOT NULL,
    is_eol                   BOOLEAN NOT NULL,
    eol_from                 DATE,
    is_maintained            BOOLEAN NOT NULL DEFAULT FALSE,
    latest_version_in_cycle  TEXT,
    UNIQUE (technology_name, release_cycle)
);

CREATE TABLE eol_product_fetch_state (
    technology_name  TEXT PRIMARY KEY,
    fetched_at       TIMESTAMPTZ NOT NULL
);

-- EOL_CORRELATION: a per-target scan_run created by EolCorrelationScheduler whenever a
-- target's fingerprinted tech has a newly-cached EOL/approaching-EOL match, purely so
-- the resulting findings go through the normal ResultIngestionService/scan_run
-- machinery - same "lightweight synthetic run" pattern CT_CHECK/CVE_CORRELATION
-- established.
ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_triggered_by_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_triggered_by_check
    CHECK (triggered_by IN ('SCHEDULED', 'MANUAL', 'CT_CHECK', 'CT_TRIGGERED', 'CVE_CORRELATION', 'EOL_CORRELATION'));

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('TECH_EOL_SOFTWARE_DETECTED', 'EXPOSURE', 'MEDIUM',
 'End-of-life software detected',
 'The fingerprinted release cycle of a detected technology has reached end-of-life and receives no further security patches from its vendor, even for vulnerabilities not yet discovered - a forward-looking risk distinct from any specific known CVE.',
 'Upgrade to a still-maintained release cycle of this software as soon as practical.',
 1.0),
('TECH_EOL_APPROACHING', 'EXPOSURE', 'LOW',
 'Software approaching end-of-life',
 'The fingerprinted release cycle of a detected technology is scheduled to reach end-of-life within the next 90 days - an advance heads-up to plan an upgrade before it actually stops receiving patches.',
 'Plan and schedule an upgrade to a newer release cycle before its end-of-life date.',
 0.3);
