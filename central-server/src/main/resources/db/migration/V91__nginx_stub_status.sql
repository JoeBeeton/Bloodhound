-- EXPOSURE_NGINX_STUB_STATUS: a direct parallel to EXPOSURE_APACHE_SERVER_STATUS (V86) - nginx's
-- own stub_status module, a classic scanner checklist item, routinely left enabled and
-- world-reachable by default on a stock nginx install. Discloses less per-request detail than
-- Apache's mod_status (no client IPs/URLs, just aggregate connection and request counts), but
-- still confirms internal infrastructure load/capacity - useful denial-of-service targeting
-- recon. Matched on the module's own fixed, unchanging "server accepts handled requests" label
-- line, not just a 200 at a common path, so an unrelated app health-check route (very commonly
-- living at /status) can't false-positive.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_NGINX_STUB_STATUS', 'EXPOSURE', 'MEDIUM',
 'nginx stub_status page exposed',
 'The nginx stub_status module is publicly reachable, disclosing aggregate connection and request counts for this server - internal infrastructure load/capacity information useful for targeting denial-of-service attacks.',
 'Restrict the stub_status location to trusted internal IPs only (nginx''s allow/deny directives), or disable the module entirely if not needed.',
 0.4);
