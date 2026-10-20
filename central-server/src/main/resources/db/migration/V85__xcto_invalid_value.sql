-- HEADER_XCTO_INVALID_VALUE: closes a gap in the existing X-Content-Type-Options check (only
-- presence was checked, same "quality not just presence" gap HEADER_CSP_WEAK_POLICY and
-- HEADER_REFERRER_POLICY_UNSAFE already closed for their own headers). X-Content-Type-Options
-- recognizes exactly one value, nosniff - anything else (a typo, a stray duplicate, a
-- copy-pasted garbage value) is silently ignored by every browser, making it functionally
-- identical to the header being missing entirely while looking, to a human skimming raw headers,
-- like it's set correctly. Both Mozilla Observatory and securityheaders.com check the value, not
-- just presence, for exactly this reason.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('HEADER_XCTO_INVALID_VALUE', 'HEADERS', 'LOW',
 'X-Content-Type-Options set to an invalid value',
 'The X-Content-Type-Options header is present, but its value isn''t nosniff - the only value browsers recognize. Any other value is silently ignored, leaving the response just as open to MIME-sniffing as if the header were missing entirely.',
 'Set the header to exactly "X-Content-Type-Options: nosniff".',
 0.3);
