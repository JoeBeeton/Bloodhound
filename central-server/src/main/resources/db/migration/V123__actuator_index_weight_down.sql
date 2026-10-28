-- EXPOSURE_ACTUATOR_INDEX was already re-graded to LOW in V119, specifically because
-- ExposedPathDecisionLogic#decide only ever fires this rule when none of the sensitive subpath
-- rules (heapdump/env/beans/mappings/configprops/threaddump/loggers) fired - health/info are
-- deliberately excluded from that gate (see decide()'s own comment) since they're commonly
-- intentional and not a real disclosure. That same gate means a 0.1 weight here never
-- under-counts a target that also has a genuinely sensitive actuator endpoint exposed - those
-- cases are a different rule_id (one of the HIGH/CRITICAL ones above) raised instead, not this
-- one at a discount.
UPDATE rules_catalog SET weight = 0.1 WHERE rule_id = 'EXPOSURE_ACTUATOR_INDEX';
