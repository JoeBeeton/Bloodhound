-- NETWORK_SMB_NETBIOS_EXPOSED was raising CRITICAL from a single successful TCP connect on
-- 135/139/445 alone - no retry, no payload, no protocol confirmation at all (PortScanDecisionLogic
-- / DeepPortScanDecisionLogic, pre-dating this migration). Found live on app.examplefinance.com:135:
-- one TCP connect succeeded, then every one of five later re-tests (two protocols, two address
-- families, direct DCE/RPC bind and SMB negotiate attempts) got nothing back - a transient
-- listener or a stateful firewall/load balancer accepting the handshake with nothing real behind
-- it, not a genuinely exposed, wormable Windows service.
--
-- Both decision-logic classes now only keep NETWORK_SMB_NETBIOS_EXPOSED's CRITICAL rating when
-- SmbRpcConfirmationProbe actually gets a valid SMB2 negotiate or DCE/RPC bind reply back from the
-- port. A bare-TCP-connect-only hit is reported here instead, at MEDIUM - a different rule_id
-- rather than a severity change on the same one, since FindingReconciler never upgrades an
-- already-OPEN finding's severity on a later, stronger detection (see
-- DeepPortScanDecisionLogic's own class javadoc) - a transient unconfirmed hit must not
-- permanently cap this at MEDIUM if a later scan does confirm it.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_SMB_NETBIOS_PORT_OPEN_UNCONFIRMED', 'NETWORK', 'MEDIUM',
 'Port used by SMB/NetBIOS/RPC accepted a connection, but the protocol itself didn''t respond',
 'A port used by SMB, NetBIOS, or the Windows RPC endpoint mapper (445/139/135) accepted a plain TCP connection, but a follow-up SMB negotiate/DCE-RPC bind probe got no valid protocol reply. This is often a transient listener, a stateful firewall or load balancer accepting the TCP handshake with nothing real behind it, or a brief window where a genuine service was starting or stopping - not yet strong enough evidence of a continuously-exposed Windows service to warrant a Critical rating on its own.',
 'Re-check this port on a later scan. If it keeps appearing here rather than escalating to the Critical NETWORK_SMB_NETBIOS_EXPOSED finding, it is likely not a real exposed service - but if 445/139/135 should never answer at all from the internet, block them at the perimeter firewall regardless.',
 1.0);
