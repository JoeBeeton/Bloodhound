-- DNS_SPF_MISSING_ALL_MECHANISM: closes a gap the existing SPF too-permissive check
-- (DNS_SPF_TOO_PERMISSIVE) only partly covers - it catches a record explicitly ending in +all or
-- ?all, but not a record with NO all mechanism at all. RFC 7208 2.6.7: a sender IP matching none
-- of the earlier mechanisms, with no all mechanism present, evaluates to Neutral - the exact same
-- practical effect as an explicit ?all, just reached by omission rather than intent. The record's
-- own author plainly meant to restrict senders (otherwise why write any mechanisms at all) but
-- forgot to terminate it, so mail from an unauthorized server still gets no SPF signal against
-- it. redirect= correctly isn't flagged - it takes over the all-mechanism's role entirely per RFC
-- 7208 6.1.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_SPF_MISSING_ALL_MECHANISM', 'DNS', 'MEDIUM',
 'SPF record has no terminating all mechanism',
 'This SPF record has no all mechanism (and no redirect= taking its place), so RFC 7208 evaluates any sender IP matching none of the earlier mechanisms as Neutral - the same practical effect as an explicit ?all, just reached by omission rather than intent. Mail from an unauthorized server gets no SPF signal against it at all.',
 'Add a terminating all mechanism (-all to hard-fail unauthorized senders, or ~all to soft-fail) at the end of the record.',
 0.5);
