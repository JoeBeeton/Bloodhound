-- EXPOSURE_VNC_NO_AUTH: VNC's own RFB protocol handshake directly reveals whether a server
-- requires a password at all, without needing to actually attempt a login. Port 5900 was already
-- bucketed generically under ADMIN_DB_PORTS (PORT_UNEXPECTED_OPEN_ADMIN_SERVICE) with no
-- confirmation of actual unauthenticated access - the same kind of upgrade
-- EXPOSURE_REDIS_UNAUTH/EXPOSURE_ELASTICSEARCH_UNAUTH already represent over a bare port-open
-- check for their own services. Matched on the server offering only security type 1 ("None") in
-- its handshake reply, confirmed to be a real RFB server via the fixed 12-byte version banner
-- first. CRITICAL: full remote desktop access, no password required at all.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_VNC_NO_AUTH', 'EXPOSURE', 'CRITICAL',
 'VNC reachable with no authentication required',
 'A VNC server on its default port (5900) offers only the "None" security type, confirmed via the RFB protocol''s own handshake, meaning any connection is granted full remote desktop access with no password or other authentication at all.',
 'Configure a VNC password immediately (or disable the "None" security type in the server''s configuration), and restrict network access to the VNC port to trusted hosts only.',
 1.0);
