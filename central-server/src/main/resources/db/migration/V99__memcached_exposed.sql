-- NETWORK_MEMCACHED_EXPOSED: memcached's default port (11211) was already in TcpConnectPortScanner's
-- new curated-port list this migration adds it to - previously absent entirely, a complete blind
-- spot in Tier 1's fastest scan tier even though Tier 2's full-range naabu scan would have seen
-- the open port with no meaningful classification. Memcached ships with no authentication at all
-- by default, so a reachable instance discloses whatever an application cached in it - often
-- including session tokens and query results - to anyone who connects. Internet-exposed memcached
-- servers were also the vector behind the largest DDoS amplification attacks on record (the 2018
-- 1.3 Tbps attack on GitHub), since its UDP protocol variant has no source-address validation and
-- an amplification factor that can exceed 50,000x. Shares the SAME rule_id across Tier1/Tier2 (see
-- NETWORK_SMB_NETBIOS_EXPOSED's own precedent) so central-server's dedup treats a Tier1-flagged
-- and Tier2-flagged instance of the same port as one finding. CRITICAL, same tier as
-- NETWORK_SMB_NETBIOS_EXPOSED - both are unauthenticated-by-default protocols never designed for
-- internet exposure.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_MEMCACHED_EXPOSED', 'NETWORK', 'CRITICAL',
 'Memcached reachable from the internet',
 'Memcached''s default port (11211) was found open and reachable from the internet. Memcached ships with no authentication at all by default, so a reachable instance discloses whatever an application cached in it - often including session tokens and query results - to anyone who connects. Internet-exposed memcached servers were also the vector behind the largest DDoS amplification attacks on record, since its UDP protocol variant has no source-address validation and an amplification factor that can exceed 50,000x.',
 'Bind memcached to localhost or a private network interface only, and firewall port 11211 (both TCP and UDP) from the internet. If UDP support is not required, disable it explicitly (-U 0).',
 1.0);
