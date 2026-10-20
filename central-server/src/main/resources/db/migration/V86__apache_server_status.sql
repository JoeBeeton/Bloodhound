-- EXPOSURE_APACHE_SERVER_STATUS: closes a gap against a classic scanner checklist item (Nikto's
-- default checks include /server-status) this product's exposure-path catalog had no equivalent
-- for. Apache's mod_status page, when left world-reachable (routinely the default on a stock
-- install), discloses every currently in-flight request - client IP addresses and the full
-- URLs/query strings being processed, which can themselves carry session tokens or other
-- sensitive parameters. Matched on the page's own distinctive "Apache Server Status for" heading,
-- not just a 200 at the path, so an unrelated app route happening to live at the same path can't
-- false-positive.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_APACHE_SERVER_STATUS', 'EXPOSURE', 'MEDIUM',
 'Apache mod_status page exposed',
 'The Apache mod_status page (/server-status) is publicly reachable, disclosing currently in-flight requests - including client IP addresses and the URLs/query strings being processed, which can themselves carry session tokens or other sensitive parameters.',
 'Restrict /server-status to trusted internal IPs only (Apache''s Require/Allow directives), or disable mod_status entirely if not needed.',
 0.5);
