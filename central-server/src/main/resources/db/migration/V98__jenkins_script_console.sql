-- EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH: Jenkins's Groovy script console (/script),
-- unauthenticated, is direct remote code execution - run arbitrary Groovy, which can shell out, on
-- the Jenkins host. A classic, heavily-flagged misconfiguration (Shodan/Censys dorks and Nuclei
-- templates both target it directly) that every major commercial/OSS scanner checks for and this
-- product had no equivalent for. Matched on Jenkins's own distinctive script-console page copy,
-- present only when the page actually rendered rather than redirecting to a login form. CRITICAL,
-- same tier as EXPOSURE_DOCKER_API/EXPOSURE_KUBERNETES_API_UNAUTH - direct unauthenticated RCE.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'Jenkins script console exposed without authentication',
 'Jenkins''s Groovy script console is publicly reachable without authentication, allowing arbitrary Groovy code execution - equivalent to full remote code execution on the Jenkins host.',
 'Enable Jenkins''s security realm and authorization strategy so the script console requires an authenticated administrator, and firewall the Jenkins port to trusted hosts only.',
 1.0);
