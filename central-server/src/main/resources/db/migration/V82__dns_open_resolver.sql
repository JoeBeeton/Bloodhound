-- NETWORK_DNS_OPEN_RESOLVER: a classic DNS-abuse check (RFC 5358, every major network scanner's
-- "open recursive resolver" plugin) this product had no equivalent for. DnsZoneFetcher already
-- connects directly to each of a target's own authoritative nameservers for the AXFR and
-- lame-delegation checks - this reuses that exact connection, asking a different question: does
-- the nameserver answer recursive queries for domains it has no authority over, from any client,
-- not just this organization's own infrastructure. A canary name the nameserver can't possibly be
-- authoritative for (a.root-servers.net, one of the most stable A records in DNS) getting a real
-- answer back means yes. MEDIUM: an operational misconfiguration that lets a third party abuse
-- this server as a DNS-amplification DDoS reflector, not a direct compromise of the target itself.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_DNS_OPEN_RESOLVER', 'NETWORK', 'MEDIUM',
 'DNS server is an open recursive resolver',
 'This nameserver answers recursive DNS queries for domains it has no authority over, from any client on the internet, not just this organization''s own infrastructure. Open resolvers are a classic DNS-amplification DDoS reflector (RFC 5358): an attacker spoofing a victim''s source IP can use this server to send the victim amplified, unwanted traffic.',
 'Disable recursion for clients outside this organization''s own network (e.g. BIND''s "allow-recursion", or the equivalent on your DNS server software), or restrict the server to answering only as authoritative for its own zones.',
 0.5);
