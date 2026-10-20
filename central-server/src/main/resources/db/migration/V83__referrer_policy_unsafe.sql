-- HEADER_REFERRER_POLICY_UNSAFE: closes a gap in the existing Referrer-Policy check (only
-- presence was checked, same "quality not just presence" gap HEADER_CSP_WEAK_POLICY closed for
-- CSP). unsafe-url is the worst possible value: it sends the complete referrer URL - full path
-- and query string, which routinely carries session tokens, API keys, search terms, or other
-- PII - on every navigation, including cross-origin requests and HTTPS-to-HTTP downgrades, where
-- every other policy value withholds at least the path. A well-known header-quality check
-- (Mozilla Observatory, securityheaders.com).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('HEADER_REFERRER_POLICY_UNSAFE', 'HEADERS', 'MEDIUM',
 'Referrer-Policy set to unsafe-url',
 'A Referrer-Policy header is present, but its value is (or falls back to) unsafe-url - the worst possible setting. It sends the complete referrer URL, including the full path and query string (which routinely carries session tokens, API keys, or other sensitive data), on every navigation: cross-origin requests and even HTTPS-to-HTTP downgrades, where every other policy value withholds at least the path.',
 'Replace unsafe-url with a safer policy such as strict-origin-when-cross-origin (the current browser default) or no-referrer.',
 0.4);
