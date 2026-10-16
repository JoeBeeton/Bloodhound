-- DNS_DKIM_WEAK_KEY: closes a gap in the existing DKIM detection (DNS_DKIM_NOT_DETECTED only
-- checked for presence at common selector names, never key strength). Verified live before
-- building: github.com's "google" selector carries a real 2048-bit RSA key, Microsoft's
-- "selector2" (onmicrosoft.com) carries a real 1024-bit RSA key - both decoded and measured
-- correctly via the JDK's own X509EncodedKeySpec/RSAPublicKey, no manual ASN.1 parsing needed.
-- MEDIUM: a real, exploitable weak-crypto gap (a 1024-bit RSA key is within reach of realistic
-- factoring resources, letting mail be forged as DKIM-valid), same tier as other weak-crypto
-- findings in this catalog (e.g. TLS weak cipher suites).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_DKIM_WEAK_KEY', 'DNS', 'MEDIUM',
 'DKIM record uses a weak RSA key',
 'A DKIM TXT record was found with an RSA public key below 2048 bits - the current minimum recommended by DKIM deployment guidance (M3AAWG, dkim.org), matching the same line NIST drew for RSA generally in 2013. A key this size is within reach of realistic factoring resources, letting an attacker forge DKIM-valid mail from this domain.',
 'Rotate the DKIM key pair to a 2048-bit (or larger) RSA key, or migrate to an ed25519 key (RFC 8463), and publish the new public key at the same selector.',
 0.7);
