-- EXPOSURE_KUBERNETES_API_UNAUTH: a common, high-severity cloud attack-surface finding (Shodan
-- dashboards have dedicated searches for this; real incidents include Tesla's 2018 exposed
-- Kubernetes dashboard) this product had no equivalent for at all - port 6443 wasn't even
-- scanned before this. Probes GET /api/v1/namespaces over HTTPS (the Kubernetes API server never
-- serves plain HTTP), matching specifically on "kind":"NamespaceList" - the real response shape
-- only returned when the request is actually permitted, never for a properly-secured cluster
-- that correctly denies anonymous access with a "kind":"Status"/"reason":"Forbidden" response
-- instead. Required new altPortHttps plumbing in ExposedPathFetcher (a permissive
-- X509ExtendedTrustManager, since the cluster's own self-signed CA is essentially never in any
-- public trust store) - live-verified against a local self-signed HTTPS server before shipping.
-- CRITICAL: confirmed anonymous read access to the control plane itself, not just an application.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_KUBERNETES_API_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'Kubernetes API server allows anonymous access',
 'The Kubernetes API server is reachable on its standard port (6443) and answers an authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the cluster''s real namespace list. Anonymous read access to cluster-management data is often a foothold for broader cluster compromise - this is the control plane itself, not just an application.',
 'Disable anonymous authentication on the API server (--anonymous-auth=false), and ensure the API server is not reachable from the public internet at all - restrict it to a private network or VPN.',
 1.0);
