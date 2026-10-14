-- 3 new TLS rules closing gaps found by a capability comparison against Qualys SSL Labs and
-- EASM competitor methodology docs (SecurityScorecard/BitSight/UpGuard). SSLv3 detection needed
-- no new rule - it was added as another protocol value under the existing TLS_WEAK_PROTOCOL_SUPPORTED
-- rule, the same way TLSv1/TLSv1.1 already share it. Weights follow this category's existing
-- convention (see TLS_CERT_SIGNATURE_ALGORITHM_WEAK/TLS_CERT_KEY_TOO_SHORT at 1.2 for HIGH, and
-- EMAIL_DMARC_PCT_BELOW_100/DNS_DKIM_NOT_DETECTED at 0.4-0.5 for informational LOW findings).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('TLS_NO_FORWARD_SECRECY', 'TLS', 'MEDIUM',
 'No forward secrecy',
 'The negotiated cipher suite does not use an ephemeral (ECDHE/DHE) key exchange, meaning this connection''s session key is derived from the server''s long-term private key rather than a fresh per-session one. If that private key is ever compromised, every past session recorded by an eavesdropper (not just future ones) can be decrypted retroactively - the exact property forward secrecy exists to prevent.',
 'Prefer/require ECDHE (or DHE) cipher suites in the server''s TLS configuration, and disable plain RSA-key-exchange suites.',
 0.8),
('TLS_1_3_NOT_SUPPORTED', 'TLS', 'LOW',
 'TLS 1.3 not supported',
 'This host does not negotiate TLS 1.3, the current protocol version. Qualys SSL Labs caps its grade at A- for a server missing it - every supported connection is still using an older protocol generation, with weaker default cipher/handshake choices and strictly more historical attack surface than 1.3 was designed to remove.',
 'Enable TLS 1.3 support in the server''s TLS configuration - most modern web servers and load balancers support it with a configuration change alone.',
 0.3),
('TLS_HSTS_NOT_ON_PRELOAD_LIST', 'TLS', 'LOW',
 'HSTS preload token present but domain is not on the real preload list',
 'The Strict-Transport-Security header includes the preload token, but hstspreload.org''s own status API confirms this domain is not actually included in the list browsers ship (it may never have been submitted, or may have since been removed). Unlike TLS_HSTS_PRELOAD_NOT_ELIGIBLE (which checks whether the header''s own values meet the submission bar), this checks the real-world outcome: browsers give this site no preload protection regardless of how the header reads.',
 'Submit the domain at hstspreload.org once the policy meets its eligibility bar, or remove the preload token from the header if it is not actually intended to be submitted.',
 0.3);
