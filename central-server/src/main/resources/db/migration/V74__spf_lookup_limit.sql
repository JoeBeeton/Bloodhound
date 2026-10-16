-- DNS_SPF_LOOKUP_LIMIT_EXCEEDED: closes a gap found comparing this product's SPF checks against
-- dedicated email-security tools (MXToolbox et al.) - RFC 7208 4.5/4.5 already covered (missing,
-- multiple records, too permissive), but not 4.6.4's 10-lookup limit, arguably the single most
-- common real-world SPF misconfiguration (chaining several third-party ESP/CRM includes adds up
-- fast) and one invisible to a human just reading the top-level record. Weight matches
-- DNS_SPF_MISSING's own HIGH-tier precedent (see V4) since exceeding the limit has the same
-- practical effect: most mail servers checking SPF treat the domain as if it had none at all.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_SPF_LOOKUP_LIMIT_EXCEEDED', 'DNS', 'HIGH',
 'SPF record exceeds the 10-lookup limit',
 'This domain''s SPF record requires more than 10 DNS "lookup" mechanisms (include/a/mx/ptr/exists/redirect) once every nested include is followed - RFC 7208 mandates a hard PermError past this limit, meaning most mail servers checking SPF for this domain treat it as if SPF were entirely broken, regardless of how carefully the policy itself was written.',
 'Reduce the number of include: mechanisms (flatten rarely-changing third-party includes into direct ip4/ip6 ranges where the provider publishes them, or drop providers no longer in use) until the total lookup count is at or under 10.',
 1.0);
