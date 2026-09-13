-- Added by the rules audit: nuclei's mismatched-ssl-certificate template had flagged two hosts
-- in this deployment (a cert for tsysnotificationifservice.prod.example.finance served on the
-- -v1-0 variant of that name), but that only runs in Tier 2 against authorized targets. The
-- TLS module already holds the leaf certificate from its permissive handshake, so the check is
-- free at Tier 1 - see TlsDecisionLogic#certCovers for the RFC 6125 name matching.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('TLS_CERT_HOSTNAME_MISMATCH', 'TLS', 'HIGH',
 'TLS certificate does not match hostname',
 'The certificate presented for this host is not valid for its name - none of its Subject Alternative Names cover it. Every browser and API client will refuse the connection (or users will be trained to click through warnings); the host is typically serving another site''s certificate through a shared load balancer or a copy-pasted config.',
 'Issue a certificate that includes this hostname in its Subject Alternative Names (or a wildcard for its parent), or stop serving this name from an endpoint whose certificate does not cover it.', 1.2);
