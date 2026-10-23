-- A rules-parity review found SSH (22) was scanned at Tier 1 (TcpConnectPortScanner.CURATED_PORTS)
-- but produced no finding either way when open - unlike Docker (2375/2376) and Elasticsearch
-- (9200), which also get a real application-level probe elsewhere (EXPOSURE_DOCKER_API,
-- EXPOSURE_ELASTICSEARCH_UNAUTH), SSH has no Tier 1 check at all; the negotiable-algorithm check
-- (NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED) is Tier 2 only. Deliberately INFO and tier1-eligible:
-- this is context (plenty of legitimate infrastructure runs SSH on 22), not a vulnerability, so
-- it's weighted at 0 the same way other presence-only INFO rules are.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_SSH_PORT_REACHABLE', 'NETWORK', 'INFO',
 'SSH service reachable from the internet',
 'Port 22 (SSH) was found open and reachable. Not a vulnerability on its own - this is informational, the same role a verbose server banner plays elsewhere - but worth knowing when reviewing a host''s overall exposure.',
 'No action required unless SSH access was not intended to be internet-facing at all, in which case restrict it to a VPN or allowlisted source range. A deep scan against an authorized target also checks for negotiable weak key-exchange/host-key/cipher/MAC algorithms.',
 0);
