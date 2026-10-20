-- DNS_SOA_RETRY_EXCEEDS_REFRESH: a classic DNS-hygiene check (RFC 1912 2.2, flagged by intoDNS,
-- DNSinspect, and most zone-health report tools) this product's SOA interpretation had never
-- covered - only the serial's own staleness (DNS_SOA_SERIAL_STALE) was checked, never the
-- refresh/retry relationship. RFC 1912: retry (how often a secondary re-attempts a FAILED
-- refresh) should be smaller than refresh (the normal successful re-check interval) - otherwise a
-- secondary that misses one refresh gets no extra chances before the next regularly scheduled one
-- anyway, defeating retry's purpose. LOW: a structural zone-hygiene defect, not an active
-- vulnerability, same tier as DNS_SOA_SERIAL_STALE.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_SOA_RETRY_EXCEEDS_REFRESH', 'DNS', 'LOW',
 'SOA retry interval is not shorter than the refresh interval',
 'RFC 1912 2.2 says the SOA retry value (how often a secondary nameserver re-attempts a failed zone refresh) should be smaller than the refresh value (the normal successful re-check interval). Here retry is equal to or larger than refresh, so a secondary that misses one refresh gets no extra chances before the next regularly scheduled one anyway - a secondary can drift stale for longer than intended after a transient outage on the primary nameserver.',
 'Set the zone''s SOA retry value below its refresh value (common values: refresh 86400, retry 7200).',
 0.3);
