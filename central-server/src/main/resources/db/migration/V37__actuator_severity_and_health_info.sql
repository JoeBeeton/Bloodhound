-- Two changes to the existing Spring Boot Actuator exposure rules:
--
-- 1. /actuator/threaddump, /actuator/loggers, and the bare /actuator index
--    were seeded as MEDIUM in V7. Re-graded to HIGH: each discloses real
--    internal state (thread stacks, the full sub-endpoint map) to an
--    unauthenticated caller, which is worse than "medium" in practice.
--    heapdump/env stay CRITICAL and beans/mappings/configprops stay HIGH -
--    unchanged.
--
-- 2. /actuator/health and /actuator/info were never probed at all before
--    now (a genuine gap, not a re-mapping) - added as two new rule_ids at
--    INFO severity, since both are near-universally intentional (load
--    balancer health checks, build/version banners) rather than a real
--    exposure.
--
-- rules_catalog rows are updated in place (not re-inserted) since these
-- rule_ids already exist from V7; UPDATE keeps this migration idempotent-safe
-- against re-running on a fresh database that already has V7 applied.

UPDATE rules_catalog SET default_severity = 'HIGH', weight = 1.3
WHERE rule_id IN ('EXPOSURE_ACTUATOR_THREADDUMP', 'EXPOSURE_ACTUATOR_LOGGERS', 'EXPOSURE_ACTUATOR_INDEX');

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_ACTUATOR_HEALTH', 'EXPOSURE', 'INFO',
 'Spring Boot Actuator health endpoint exposed',
 'The /actuator/health endpoint is publicly reachable. This is commonly intentional (used by load balancers/orchestrators for health checks) and is reported for visibility only.',
 'No action needed if intentional; otherwise disable or authenticate the health actuator endpoint.', 0.3),
('EXPOSURE_ACTUATOR_INFO', 'EXPOSURE', 'INFO',
 'Spring Boot Actuator info endpoint exposed',
 'The /actuator/info endpoint is publicly reachable. This is commonly intentional (build/version banners) and is reported for visibility only.',
 'No action needed if intentional; otherwise disable or authenticate the info actuator endpoint.', 0.3);
