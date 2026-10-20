-- WHOIS_DOMAIN_PENDING_DELETE: closes a gap in the existing WHOIS status-code interpretation
-- (WhoisDecisionLogic already parsed EPP statusCodes for WHOIS_NO_TRANSFER_LOCK, but never
-- checked for pendingDelete/redemptionPeriod). These two statuses mean a registration has
-- ALREADY lapsed and is in ICANN's deletion pipeline (expired -> auto-renew grace ->
-- redemptionPeriod -> pendingDelete -> released) - a far more urgent, already-happening signal
-- than WHOIS_EXPIRY_APPROACHING's 30-day forecast. Once released, the domain can be registered by
-- anyone, who inherits whatever trust, inbound mail, or traffic is still pointed at it - the same
-- hijack shape SUBDOMAIN_DANGLING_CNAME already covers for a deleted cloud resource, applied to
-- the apex registration itself. CRITICAL: an already-in-progress, time-critical loss of the
-- domain itself, not a forecast.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('WHOIS_DOMAIN_PENDING_DELETE', 'WHOIS', 'CRITICAL',
 'Domain registration has lapsed and is pending deletion',
 'This domain''s WHOIS/RDAP status shows pendingDelete or redemptionPeriod, meaning the registration has already expired and the domain is in ICANN''s deletion pipeline. Once released it can be registered by anyone, who could then hijack residual trust, inbound email, or traffic still pointed at this domain.',
 'Contact the registrar immediately to redeem the domain (a redemption fee applies during redemptionPeriod; pendingDelete is no longer redeemable and the domain will be released to the public).',
 1.0);
