-- Milestone 3: the rules catalog, the findings table, and its dedup/resolution
-- indexes. Findings are a target-level rolling set, not per-run rows - a
-- reported finding that already exists OPEN for (target_id, rule_id,
-- affected_asset) is left alone (just "touched"); one that stops reproducing
-- gets marked RESOLVED. See ResultIngestionService/FindingReconciler.

-- Seed/reference data for scoring weights and UI copy. Not user-editable in
-- Phase 1 - just enough for a rule_id to resolve to display text and a
-- scoring weight when Milestone 5 builds the scoring engine.
CREATE TABLE rules_catalog (
    rule_id              TEXT PRIMARY KEY,
    category             TEXT NOT NULL,
    default_severity     TEXT NOT NULL CHECK (default_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title                TEXT NOT NULL,
    description          TEXT NOT NULL,
    remediation_advice   TEXT NOT NULL,
    weight               NUMERIC NOT NULL DEFAULT 1.0,
    enabled              BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE findings (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Most recently associated run (bumped every time a reproduced finding is
    -- "touched"); first_detected_scan_run_id below stays fixed at creation.
    scan_run_id                 UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    target_id                   UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_type                 TEXT NOT NULL,
    -- Soft reference, not a hard FK to rules_catalog: a worker module's
    -- output shouldn't be able to fail ingestion because a catalog seed row
    -- is missing/renamed - the catalog is reference/scoring data, not a
    -- referential-integrity gate on what findings can exist.
    rule_id                     TEXT NOT NULL,
    severity                    TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    category                    TEXT NOT NULL,
    title                       TEXT NOT NULL,
    description                 TEXT NOT NULL,
    evidence                    JSONB NOT NULL DEFAULT '{}',
    affected_asset              TEXT NOT NULL,
    first_detected_scan_run_id  UUID NOT NULL REFERENCES scan_runs(id),
    status                      TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'RESOLVED', 'ACCEPTED_RISK')),
    resolved_at                 TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_target_status ON findings(target_id, status);
-- The dedup-key lookup ResultIngestionService runs on every ingested result.
CREATE INDEX idx_findings_target_rule_asset ON findings(target_id, rule_id, affected_asset);

-- Seed rows for Milestone 3's two modules (DNS posture, HTTP headers). Later
-- milestones append more rows as they add modules - this is reference/UI
-- copy, not something an endpoint writes to yet.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_SPF_MISSING', 'DNS', 'HIGH',
 'Missing SPF record',
 'No Sender Policy Framework record was found, allowing any server to send email appearing to originate from this domain.',
 'Publish an SPF TXT record listing authorized sending servers.', 1.0),
('DNS_SPF_TOO_PERMISSIVE', 'DNS', 'MEDIUM',
 'Overly permissive SPF record',
 'The SPF record ends in +all or ?all, which allows any server (or fails open) to send mail as this domain.',
 'Change the SPF qualifier to ~all (softfail) or -all (hardfail) once all legitimate senders are enumerated.', 1.0),
('DNS_DMARC_MISSING', 'DNS', 'HIGH',
 'Missing DMARC record',
 'No DMARC record was found at _dmarc.<domain>, so spoofed mail claiming to be from this domain is not policed.',
 'Publish a DMARC TXT record at _dmarc.<domain> starting with v=DMARC1.', 1.0),
('DNS_DMARC_POLICY_NONE', 'DNS', 'MEDIUM',
 'DMARC policy set to none',
 'A DMARC record exists but its policy is p=none, meaning failing messages are only monitored, not rejected or quarantined.',
 'Move the DMARC policy to p=quarantine or p=reject once monitoring confirms legitimate senders pass alignment.', 1.0),
('DNS_CAA_MISSING', 'DNS', 'LOW',
 'Missing CAA record',
 'No CAA record restricts which Certificate Authorities may issue certificates for this domain.',
 'Publish a CAA record naming your authorized CA(s) to reduce the risk of mis-issued certificates.', 1.0),
('DNSSEC_NOT_ENABLED', 'DNS', 'MEDIUM',
 'DNSSEC not enabled',
 'No DNSKEY records were found for this zone, indicating the zone is not signed with DNSSEC.',
 'Enable DNSSEC signing with your DNS provider/registrar.', 1.0),
('HEADER_CSP_MISSING', 'HEADERS', 'MEDIUM',
 'Missing Content-Security-Policy header',
 'The response has no Content-Security-Policy header, reducing protection against XSS and data-injection attacks.',
 'Define and roll out a Content-Security-Policy header appropriate to the application.', 1.0),
('HEADER_XFO_MISSING', 'HEADERS', 'LOW',
 'Missing X-Frame-Options header',
 'The response has no X-Frame-Options header, leaving the site potentially vulnerable to clickjacking.',
 'Add X-Frame-Options: DENY or SAMEORIGIN (or an equivalent frame-ancestors CSP directive).', 1.0),
('HEADER_XCTO_MISSING', 'HEADERS', 'LOW',
 'Missing X-Content-Type-Options header',
 'The response has no X-Content-Type-Options: nosniff header, allowing browsers to MIME-sniff responses.',
 'Add X-Content-Type-Options: nosniff.', 1.0),
('HEADER_REFERRER_POLICY_MISSING', 'HEADERS', 'INFO',
 'Missing Referrer-Policy header',
 'The response has no Referrer-Policy header, so the browser default (often full referrer leakage) applies.',
 'Add a Referrer-Policy header, e.g. strict-origin-when-cross-origin.', 0.5),
('HEADER_PERMISSIONS_POLICY_MISSING', 'HEADERS', 'INFO',
 'Missing Permissions-Policy header',
 'The response has no Permissions-Policy header restricting browser feature access (camera, geolocation, etc.).',
 'Add a Permissions-Policy header scoped to the features the application actually needs.', 0.5),
('HEADER_SERVER_BANNER_VERBOSE', 'HEADERS', 'INFO',
 'Verbose server banner',
 'The Server or X-Powered-By header discloses specific software/version information useful for targeting known vulnerabilities.',
 'Suppress or generalize the Server/X-Powered-By headers at the web server or proxy layer.', 0.5),
('COOKIE_MISSING_SECURE_FLAG', 'HEADERS', 'MEDIUM',
 'Cookie missing Secure flag',
 'A cookie was set without the Secure flag, allowing it to be transmitted over unencrypted HTTP.',
 'Set the Secure attribute on all cookies.', 1.0),
('COOKIE_MISSING_HTTPONLY_FLAG', 'HEADERS', 'MEDIUM',
 'Cookie missing HttpOnly flag',
 'A cookie was set without the HttpOnly flag, making it readable by client-side JavaScript and easier to steal via XSS.',
 'Set the HttpOnly attribute on cookies that do not need JavaScript access.', 1.0),
('COOKIE_MISSING_SAMESITE', 'HEADERS', 'LOW',
 'Cookie missing SameSite attribute',
 'A cookie was set without a SameSite attribute, offering no baseline CSRF protection from the browser.',
 'Set SameSite=Lax or SameSite=Strict on cookies where cross-site sending is not required.', 1.0);
