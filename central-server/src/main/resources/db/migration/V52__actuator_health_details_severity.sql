-- A live finding (Spring Boot Actuator /actuator/health on a scanned banking subdomain)
-- showed the gap in EXPOSURE_ACTUATOR_HEALTH's blanket INFO severity: a bare
-- {"status":"UP"} and a full component breakdown (absolute filesystem paths, disk
-- free/total capacity, DB/SSL component state) were both being reported identically,
-- even though only the latter requires a real misconfiguration (show-details=always,
-- or an authorization check not actually being enforced for the caller) and discloses
-- genuine internal infrastructure detail. EXPOSURE_ACTUATOR_HEALTH stays INFO for the
-- bare-status case; this new rule_id covers the detailed-disclosure case at MEDIUM -
-- see ExposedPathDecisionLogic's health handling for the "components" body signature
-- that decides between the two.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_ACTUATOR_HEALTH_DETAILS', 'EXPOSURE', 'MEDIUM',
 'Spring Boot Actuator health endpoint discloses internal system details',
 'The /actuator/health endpoint returns a detailed component breakdown (e.g. absolute filesystem paths, disk free/total capacity, database or SSL/certificate component state) to an unauthenticated caller, rather than just the overall status. Spring Boot''s default for this is to show no component detail publicly, so this requires an explicit show-details=always setting or an authorization check that isn''t actually being enforced - and it discloses real internal infrastructure detail useful for reconnaissance, not just "a health check exists".',
 'Set management.endpoint.health.show-details to "never" (or "when-authorized" with authorization genuinely enforced) so unauthenticated callers see only the overall status.', 1.0);
