-- NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED: closes a gap found the same way as
-- NETWORK_SMB_NETBIOS_EXPOSED - ports 110 (POP3) and 143 (IMAP) were already in
-- TcpConnectPortScanner's scanned-port list but had no classification in
-- PortScanDecisionLogic at all, so an open cleartext mail-retrieval port produced no finding.
-- Unlike their TLS-wrapped counterparts (995/993, already scanned but correctly produce no
-- finding), these protocols send credentials and mail content unencrypted unless a client
-- separately negotiates STARTTLS after connecting - a bare open-port scan can't confirm that
-- either way, the same shallow-but-useful heuristic this codebase's existing
-- PORT_OPEN_UNENCRYPTED_MGMT (FTP/Telnet) already applies. A real, commonly-grouped item
-- (SecurityScorecard and similar attack-surface reports group Telnet/FTP/POP3/IMAP together as
-- "insecure network services").
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED', 'NETWORK', 'MEDIUM',
 'Cleartext mail retrieval protocol reachable',
 'A port used by POP3 or IMAP''s cleartext variant (110/143) was found open and reachable. Unlike their TLS-wrapped counterparts (995/993), these protocols send credentials and mail content unencrypted unless a client separately negotiates STARTTLS after connecting.',
 'Disable the cleartext port entirely if clients can use the TLS-wrapped port instead (995/993), or enforce STARTTLS and reject unencrypted authentication on the cleartext port.',
 0.5);
