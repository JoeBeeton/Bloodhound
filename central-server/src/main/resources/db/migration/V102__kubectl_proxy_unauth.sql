-- EXPOSURE_KUBECTL_PROXY_UNAUTH: `kubectl proxy`'s own default port (8001) and purpose - an
-- unauthenticated plain-HTTP proxy straight to the cluster API, normally bound to localhost for
-- local development convenience. Kubernetes' own hardening documentation specifically warns
-- against running it with a public bind address, and real-world incidents (including the 2018
-- Tesla cryptojacking breach) trace back to exactly this misconfiguration. Distinct from the
-- already-shipped EXPOSURE_KUBERNETES_API_UNAUTH (V94, the apiserver's own TLS port 6443) - this
-- is a separate, plain-HTTP exposure vector with its own default port, the same
-- same-service-different-port split already used for EXPOSURE_DOCKER_API/EXPOSURE_DOCKER_API_TLS.
-- Reuses the same "NamespaceList" response-shape fingerprint. CRITICAL, same tier as
-- EXPOSURE_KUBERNETES_API_UNAUTH - this is the control plane itself, not just an application.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_KUBECTL_PROXY_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'kubectl proxy exposed without authentication',
 'A kubectl proxy instance is publicly reachable on its default port (8001) and answers an authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the cluster''s real namespace list. kubectl proxy is meant for local development convenience and is normally bound to localhost - Kubernetes'' own hardening documentation specifically warns against running it with a public bind address, and real-world incidents (including the 2018 Tesla cryptojacking breach) trace back to exactly this misconfiguration.',
 'Stop running kubectl proxy with a public bind address (--address=0.0.0.0). If remote API access is genuinely needed, use a properly authenticated and TLS-protected path instead (e.g. the apiserver directly with client certificates, or a VPN/bastion).',
 1.0);
