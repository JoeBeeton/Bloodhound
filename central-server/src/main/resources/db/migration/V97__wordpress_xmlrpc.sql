-- EXPOSURE_WORDPRESS_XMLRPC: a classic, well-known WordPress hardening item (every major WP
-- security plugin/scanner - Wordfence, Sucuri - flags this) this product had no equivalent for.
-- xmlrpc.php, enabled by default, exposes two real abuse vectors: system.multicall lets an
-- attacker attempt thousands of login guesses in a single HTTP request (bypassing simple
-- per-request rate limiting), and pingback.ping can be abused as a server-side request forgery
-- vector to make the site itself probe arbitrary internal/external URLs. Matched on WordPress's
-- own exact, stable fault message for a GET request (rather than the POST its handler actually
-- expects) - unambiguous and requires no POST body to trigger. MEDIUM: an abuse-potential
-- hardening gap, not a direct compromise by itself.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_WORDPRESS_XMLRPC', 'EXPOSURE', 'MEDIUM',
 'WordPress xmlrpc.php enabled',
 'WordPress''s xmlrpc.php endpoint is enabled and reachable. Its system.multicall method lets an attacker attempt thousands of login guesses in a single HTTP request, bypassing simple per-request rate limiting, and its pingback.ping method can be abused as a server-side request forgery vector to make the site itself probe arbitrary internal or external URLs.',
 'Disable xmlrpc.php entirely if the site does not use the WordPress mobile app or Jetpack (which rely on it), via a security plugin or by blocking the path at the web server/reverse proxy.',
 0.5);
