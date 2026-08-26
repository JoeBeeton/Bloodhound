-- Phase 2 Milestone A: Tier 2 deep port scanning (full port range, service
-- identification), gated behind the target_authorizations/authorization_status
-- seam that's existed since Milestone 2 but nothing has used until now.

-- Enriches the same NETWORK category the Tier 1 light scan already covers.
-- PORT_UNEXPECTED_OPEN_ADMIN_SERVICE / PORT_OPEN_UNENCRYPTED_MGMT (from V7)
-- still apply here too - see DeepPortScanDecisionLogic.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_ANONYMOUS_FTP', 'NETWORK', 'CRITICAL',
 'Anonymous FTP login allowed',
 'The FTP service on this host accepts anonymous logins, potentially exposing file listings, uploads, or sensitive data to anyone without credentials.',
 'Disable anonymous FTP access, or replace FTP with an authenticated, encrypted transfer protocol such as SFTP.',
 1.0),
('NETWORK_FULL_PORT_SURFACE', 'NETWORK', 'INFO',
 'Full-range port scan summary',
 'A full 65535-port scan (beyond the Tier 1 curated common-port list) was completed against this host, giving a complete picture of its internet-reachable TCP surface.',
 'Review the reported open-port count against what is expected for this host and close anything not intentionally exposed.',
 0.0);
