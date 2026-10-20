-- EXPOSURE_WORDPRESS_USER_ENUMERATION: distinct from the already-shipped EXPOSURE_WORDPRESS_XMLRPC
-- (V97) - that one is about the RATE a brute-force attacker can guess at, this one is about WHICH
-- usernames to guess. WordPress's REST API users endpoint (/wp-json/wp/v2/users) is enabled by
-- default and, unless a hardening plugin/config restricts it, lists every registered account's
-- slug (often the real login username) and display name to anyone, unauthenticated - a classic
-- WPScan/Wordfence-flagged info disclosure that directly feeds credential-stuffing and
-- brute-force attacks. Matched on a real JSON ARRAY response carrying "slug"/"name" keys; a
-- hardened install instead returns a JSON OBJECT error ({"code":"rest_user_cannot_view",...}).
-- MEDIUM, same tier as EXPOSURE_WORDPRESS_XMLRPC - an abuse-enabling disclosure, not a direct
-- compromise by itself.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_WORDPRESS_USER_ENUMERATION', 'EXPOSURE', 'MEDIUM',
 'WordPress user enumeration via REST API',
 'WordPress''s REST API users endpoint (/wp-json/wp/v2/users) publicly lists every registered account''s slug - often the real login username - and display name. This directly feeds credential-stuffing and brute-force attacks by telling an attacker exactly which usernames to target.',
 'Restrict the REST API users endpoint to authenticated requests only (via a security plugin such as Wordfence, or a small must-use plugin filtering the rest_endpoints hook), and avoid author slugs that match real login usernames.',
 0.5);
