-- NETWORK_SMB_NETBIOS_EXPOSED: closes a gap found live - port 445 (SMB)/139 (NetBIOS Session
-- Service)/135 (MSRPC endpoint mapper) were already in TcpConnectPortScanner's scanned-port list
-- but not in PortScanDecisionLogic's ADMIN_DB_PORTS, so an open SMB port produced no finding at
-- all. These protocols were never designed for internet exposure, unlike the database/remote-
-- desktop services ADMIN_DB_PORTS otherwise covers, and have a long history of wormable,
-- pre-authentication remote code execution vulnerabilities (MS17-010/EternalBlue, exploited by
-- WannaCry and NotPetya - arguably the most damaging self-propagating malware outbreaks on
-- record, both enabled by internet-facing SMB). Folded into ADMIN_DB_PORTS so it shares that
-- set's existing promiscuous-port false-positive protection, but flagged under its own,
-- more severe rule given the exploitation history. CRITICAL, distinct from
-- PORT_UNEXPECTED_OPEN_ADMIN_SERVICE's HIGH.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_SMB_NETBIOS_EXPOSED', 'NETWORK', 'CRITICAL',
 'Windows file-sharing/RPC service reachable from the internet',
 'A port used by SMB, NetBIOS, or the Windows RPC endpoint mapper (445/139/135) was found open and reachable from the internet. These protocols were never designed for internet exposure and have a long history of wormable, pre-authentication remote code execution vulnerabilities (e.g. MS17-010/EternalBlue, exploited by WannaCry and NotPetya) - internet-facing SMB is one of the most consistently dangerous network exposures a host can have.',
 'Block inbound access to ports 445/139/135 at the perimeter firewall. These protocols should never be reachable from the public internet - restrict them to the internal network only, behind a VPN if remote access is genuinely needed.',
 1.0);
