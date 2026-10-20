-- DNS_SPF_PTR_MECHANISM_DEPRECATED: the SPF lookup-count walk (V74) already visits every
-- mechanism in the full recursive chain, including ptr - but only to count it toward the limit,
-- never to flag its own use. RFC 7208 5.5 explicitly says the ptr mechanism "SHOULD NOT be used":
-- it requires a slow reverse-then-forward DNS lookup per sender IP, is unreliable, and some mail
-- validators skip evaluating it entirely or treat its mere presence as an automatic SPF failure -
-- a real, well-known SPF hygiene check (flagged by MXToolbox, dmarcian, and most SPF validators).
-- LOW: best-practice hygiene, not an active vulnerability by itself.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_SPF_PTR_MECHANISM_DEPRECATED', 'DNS', 'LOW',
 'SPF record uses the deprecated ptr mechanism',
 'This domain''s SPF record uses the ptr (or ptr:domain) mechanism, which RFC 7208 5.5 explicitly says SHOULD NOT be used: it requires a slow reverse-then-forward DNS lookup per sender IP, is unreliable, and some mail validators skip evaluating it entirely or treat its mere presence as an automatic SPF failure.',
 'Replace the ptr mechanism with explicit ip4:/ip6:/include: mechanisms naming the actual sending infrastructure.',
 0.4);
