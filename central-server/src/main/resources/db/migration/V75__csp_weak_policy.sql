-- HEADER_CSP_WEAK_POLICY: closes a gap found comparing this product's header checks against
-- Mozilla Observatory's own CSP grading - HEADER_CSP_MISSING already covered presence, but not
-- policy quality. 'unsafe-inline'/'unsafe-eval' and a bare wildcard (*) script-src/default-src
-- source each defeat most of CSP's real protection value while still technically satisfying
-- "a CSP header exists". Weight matches HEADER_CSP_MISSING's own MEDIUM-tier precedent (see V4).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('HEADER_CSP_WEAK_POLICY', 'HEADERS', 'MEDIUM',
 'Content-Security-Policy allows unsafe or unrestricted script execution',
 'A Content-Security-Policy header is present, but its script-src/default-src directive allows ''unsafe-inline'', ''unsafe-eval'', or a bare wildcard (*) source - each of which defeats most of CSP''s real protection against injected-script attacks. A policy with ''unsafe-inline'' lets an attacker-injected inline <script> run exactly as if no policy were set at all.',
 'Remove ''unsafe-inline''/''unsafe-eval'' from script-src/default-src (use nonces or hashes for legitimate inline scripts instead) and replace a bare wildcard source with an explicit allowlist of trusted origins.',
 1.0);
