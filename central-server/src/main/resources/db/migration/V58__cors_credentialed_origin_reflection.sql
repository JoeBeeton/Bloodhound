-- Added by the rules audit's new-rule pass. HttpHeaderFetcher now sends one extra GET carrying
-- a fabricated Origin header alongside the existing check; if the response echoes that exact
-- origin back in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true,
-- the server accepts credentialed cross-origin requests from any site at all, not just an
-- allowlisted one - see HttpHeaderParser#corsReflectionFindings for the full reasoning and why a
-- bare wildcard alone is deliberately not flagged.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('CORS_CREDENTIALED_ORIGIN_REFLECTION', 'HEADERS', 'HIGH',
 'CORS reflects arbitrary Origin with credentials allowed',
 'The server echoes back whatever Origin header it receives in Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true, rather than checking the Origin against a real allowlist. Any malicious website can exploit this to make authenticated cross-origin requests using a logged-in victim''s own cookies and read the response.',
 'Validate the Origin header against an explicit allowlist of known-good origins before echoing it back, and only ever set Access-Control-Allow-Credentials: true for origins on that allowlist - never reflect an arbitrary Origin verbatim.', 1.0);
