-- Found live: two real hosts (jaja.co.uk's joinbeta/pioneers subdomains) both showed all 9
-- entries of PortScanDecisionLogic's ADMIN_DB_PORTS open at once - RDP, MySQL, Postgres, MongoDB,
-- Redis, MSSQL, Oracle, VNC, and CouchDB, simultaneously, on the same host. No real infrastructure
-- runs all nine of those unrelated vendor protocols on one box; independently confirmed live
-- against the raw sockets themselves that nothing real answers behind them (a passive read from
-- port 3306 got zero bytes despite MySQL unconditionally greeting first, and an explicit Redis
-- PING to port 6379 got no reply at all). PortScanDecisionLogic/DeepPortScanDecisionLogic now
-- detect this pattern (5+ of the 9 open at once) and report it as this single finding instead of
-- nine misleading PORT_UNEXPECTED_OPEN_ADMIN_SERVICE findings implying nine confirmed exposures.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_PROMISCUOUS_PORT_RESPONSE', 'NETWORK', 'INFO',
 'Unusually many admin/database ports appear open at once',
 'Several commonly-flagged administrative/database ports (covering multiple unrelated vendor protocols) all appear open on this host simultaneously - a pattern real infrastructure essentially never produces, and much more consistent with a firewall, load balancer, or WAF accepting TCP connections on every port than with that many distinct services genuinely being exposed.',
 'Verify directly whether any of the listed ports are actually running the service they are conventionally associated with before treating this as confirmed exposure - a bare TCP accept with no protocol response behind it is not the same as a reachable database or admin service.', 0.1);
