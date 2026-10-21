-- EXPOSURE_PGADMIN: pgAdmin's own conventional Docker-Compose port mapping (5050, pgAdmin's
-- official quick-start's own choice, copied by virtually every tutorial) - not a single true fixed
-- default the way Redis's 6379 is, since the upstream container actually listens on 80 internally.
-- Same "exposed admin login surface" finding shape as the already-shipped EXPOSURE_PHPMYADMIN/
-- EXPOSURE_ADMINER - flagged on the login console's own presence (an attack-surface/hardening
-- concern), not a confirmed authentication bypass. Matched on the page title plus a login-form
-- marker together (pgAdmin's login form uses an email field, not a plain username field like
-- phpMyAdmin/Adminer) - the same false-positive guard EXPOSURE_PHPMYADMIN already established
-- after a real false positive during Milestone 9's live verification. HIGH, same tier as
-- EXPOSURE_PHPMYADMIN.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_PGADMIN', 'EXPOSURE', 'HIGH',
 'pgAdmin console exposed',
 'A pgAdmin database-administration login console is publicly reachable.',
 'Restrict network access to the pgAdmin console to trusted hosts only, and ensure a strong master password is set.',
 1.3);
