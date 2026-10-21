-- EXPOSURE_PROMETHEUS_SERVER_UNAUTH: distinct from the already-shipped EXPOSURE_PROMETHEUS_METRICS
-- (V66, an individual application's own scraped /metrics endpoint) - this is the Prometheus
-- SERVER itself, on its own default port (9090), with its query API left open. Unauthenticated
-- access here discloses the full scrape configuration - every monitored service/job name across
-- the whole fleet, a far broader reconnaissance surface than one app's own counters. Matched on
-- the real /api/v1/status/config response's "status":"success" envelope plus the
-- scrape_configs key in its embedded YAML; a hardened install (e.g. an auth-requiring reverse
-- proxy in front) would instead return an auth challenge or error page. HIGH, same tier as
-- EXPOSURE_CONSUL_UNAUTH - broad internal infrastructure/topology disclosure, not direct RCE.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_PROMETHEUS_SERVER_UNAUTH', 'EXPOSURE', 'HIGH',
 'Prometheus server exposed without authentication',
 'The Prometheus server''s own query API is reachable on its default port (9090) without authentication, disclosing the full scrape configuration - every monitored service/job name across the whole fleet. This is distinct from, and broader than, a single application''s own exposed /metrics endpoint.',
 'Put an authenticating reverse proxy in front of the Prometheus server, or restrict access to trusted internal networks only. Prometheus has no built-in authentication of its own.',
 1.3);
