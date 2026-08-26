-- Milestone 10: CT-triggered rescans and the (dormant-by-default)
-- breach-correlation module.

-- CT_CHECK: a lightweight scan_run containing a single CT_CHECK job, created
-- by CtMonitorScheduler on a fixed interval, independent of a target's normal
-- Tier 1 scan cadence. CT_TRIGGERED: a full rescan created when a CT_CHECK
-- job finds a certificate-backed hostname not already in the subdomains
-- table - see CtCheckResultService.
ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_triggered_by_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_triggered_by_check
    CHECK (triggered_by IN ('SCHEDULED', 'MANUAL', 'CT_CHECK', 'CT_TRIGGERED'));

-- Rule for the optional BreachCorrelationModule (worker), which stays out of
-- every scan run by default - it only ever runs if an operator sets
-- HIBP_API_KEY and adds BREACH_CORRELATION to ScanRunService's module list.
-- Category BREACH sits outside ScoringEngine's fixed weight table (same as
-- WHOIS), so a breach finding is visible in the findings list/UI but never
-- affects a target's overall score.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH', 'BREACH', 'MEDIUM',
 'Domain associated with a known data breach',
 'Email addresses at this domain have appeared in a publicly known data breach, indicating credentials or personal data tied to this domain may be exposed and available to attackers.',
 'Enforce mandatory password resets for affected accounts, enable multi-factor authentication organization-wide, and monitor for credential-stuffing attempts against services using this domain.',
 1.0);
