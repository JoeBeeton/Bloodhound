-- EXPOSURE_DOCKER_API_TLS: a direct parallel to EXPOSURE_DOCKER_API (V-era pre-existing) - port
-- 2376 (Docker's TLS-secured daemon port) was already in TcpConnectPortScanner's scanned-port
-- list but had no HTTP-level confirmation check at all, only the plain-HTTP 2375 variant was
-- probed. A real, documented misconfiguration (--tls set without --tlsverify, or a server cert
-- issued with no client-CA check) leaves the full Docker API reachable to anyone who can complete
-- a TLS handshake at all - invisible to the 2375-only check. Reuses the exact same "ApiVersion"
-- response-shape fingerprint as EXPOSURE_DOCKER_API, just reached over HTTPS via the
-- altPortHttps plumbing added for EXPOSURE_KUBERNETES_API_UNAUTH (V94). CRITICAL, same tier as
-- EXPOSURE_DOCKER_API - equivalent to root access on the host either way.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_DOCKER_API_TLS', 'EXPOSURE', 'CRITICAL',
 'Docker Engine API exposed on its TLS port without client verification',
 'The Docker Engine remote API is reachable on its TLS-secured port (2376), but without requiring a trusted client certificate - a documented misconfiguration (--tls set without --tlsverify, or a server cert issued with no client-CA check) that leaves the full API open to anyone who can complete a TLS handshake. Equivalent to root access on the host.',
 'Enable --tlsverify (not just --tls) so the daemon requires and validates a client certificate signed by your own CA, or firewall this port to trusted hosts only.',
 1.0);
