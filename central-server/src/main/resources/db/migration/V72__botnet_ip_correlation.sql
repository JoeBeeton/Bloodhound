-- Botnet-C2 IP correlation over every active target's currently-known IP addresses, against
-- abuse.ch's free, no-auth Feodo Tracker feed - closes a genuine gap found comparing this
-- product's rule catalog against commercial EASM/security-rating competitors: SecurityScorecard
-- and BitSight both have a dedicated "IP Reputation"/"Botnet Infections" risk factor with no prior
-- equivalent here. Same architecture as kev_catalog/cve_lookup_cache (V13): a small feed mirrored
-- wholesale, refreshed on a timer, correlated centrally against data already collected rather than
-- as a per-scan worker module (this is IP-address data already sitting in `subdomains`, not
-- something that needs a fresh network probe per scan).
--
-- botnet_ip_cache_meta tracks "have we asked Feodo Tracker recently" as its own single-row
-- watermark, independent of botnet_ip_cache's row count - a legitimately empty "online" list
-- (confirmed a real, normal state live: only 1 of 5 total tracked IPs was "online" at the time
-- this was built) must still count as "freshly checked", or it would be re-fetched every tick.
CREATE TABLE botnet_ip_cache (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address  TEXT NOT NULL,
    malware     TEXT,
    first_seen  DATE,
    UNIQUE (ip_address)
);

CREATE TABLE botnet_ip_cache_meta (
    id          INT PRIMARY KEY,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- BOTNET_CORRELATION: a per-target scan_run (one already-COMPLETE scan_job, same "lightweight
-- synthetic run" pattern CVE_CORRELATION/EOL_CORRELATION already established) created by
-- BotnetCorrelationScheduler whenever a target has a newly-relevant IP match.
ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_triggered_by_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_triggered_by_check
    CHECK (triggered_by IN ('SCHEDULED', 'MANUAL', 'CT_CHECK', 'CT_TRIGGERED', 'CVE_CORRELATION', 'EOL_CORRELATION', 'BOTNET_CORRELATION'));

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_IP_KNOWN_BOTNET_C2', 'NETWORK', 'CRITICAL',
 'Target IP currently listed as active botnet C2 infrastructure',
 'An IP address currently resolving for this target is listed by abuse.ch''s Feodo Tracker as an actively responding ("online") command-and-control server for a tracked banking-trojan/botnet malware family. This can mean this host''s own infrastructure has been compromised and is running malware C2 software - but cloud IP addresses are also frequently reassigned between unrelated tenants, so a shared-hosting/cloud IP previously used by the botnet operator and since reassigned to this target is a real, non-malicious possibility worth ruling out first.',
 'Investigate the host at this IP immediately for signs of compromise (unexpected processes, outbound connections, unfamiliar scheduled tasks). If the host is confirmed clean, check whether the IP is on dynamically-assigned cloud infrastructure that may simply have been reused since the malware operator''s own use of it ended.',
 1.8);
