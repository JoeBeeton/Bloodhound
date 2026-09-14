-- Added by the rules audit's new-rule pass. TlsDecisionLogic's hstsFindings now checks a second,
-- stricter bar independent of TLS_HSTS_SHORT_MAX_AGE's 6-month one: hstspreload.org (the source of
-- every browser's built-in HSTS preload list) requires max-age of at least 1 year plus
-- includeSubDomains before it will accept a submission. A site whose header carries the preload
-- token without actually meeting that bar gets a false sense of protection - browsers ignore the
-- token entirely unless the site is actually on the list - see TlsDecisionLogic#hstsFindings for
-- the full reasoning.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('TLS_HSTS_PRELOAD_NOT_ELIGIBLE', 'TLS', 'LOW',
 'HSTS preload token present without meeting preload requirements',
 'The Strict-Transport-Security header includes the preload token, but hstspreload.org (the source of every browser''s built-in preload list) requires max-age of at least 1 year and includeSubDomains before it will accept a submission. The token gives a false sense of protection: browsers ignore it entirely unless the site is actually on the list, and it won''t be while the underlying policy is this weak.',
 'Either raise max-age to at least 31536000 (1 year) and add includeSubDomains to actually qualify, or remove the preload token until the policy meets hstspreload.org''s submission requirements.', 1.0);
