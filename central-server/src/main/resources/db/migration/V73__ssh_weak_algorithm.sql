-- NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED: closes a gap found comparing this product's rule catalog
-- against ssh-audit/Mozilla's OpenSSH hardening guide conventions - only a banner version grab
-- existed for SSH before (DeepPortScanModule's existing BannerDecisionLogic), nothing checking
-- the actual negotiable KEX/host-key/cipher/MAC algorithms the way TLS_WEAK_PROTOCOL_SUPPORTED/
-- TLS_WEAK_CIPHER_SUITE already do for TLS. Tier 2 only (deep scan), since it needs a full SSH
-- handshake via zgrab2 against an already-discovered open port 22, same tier as the rest of
-- DeepPortScanModule's service-identification work. Weight matches this category's existing
-- HIGH-severity convention (see PORT_UNEXPECTED_OPEN_ADMIN_SERVICE at 1.3... actually that one is
-- 1.2-1.3 tier per V66's own convention note) - 1.2 for a serious-but-not-directly-compromising
-- configuration weakness.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED', 'NETWORK', 'HIGH',
 'SSH server offers a deprecated/weak algorithm',
 'The deep scan''s SSH handshake probe found this server is willing to negotiate at least one deprecated or cryptographically weak key-exchange, host-key, cipher, or MAC algorithm - a client that still offers it (an outdated SSH client, or one deliberately downgraded by an attacker) can still use it, regardless of what a modern client would normally pick.',
 'Remove the weak algorithm(s) from the server''s SSH daemon configuration (e.g. OpenSSH''s KexAlgorithms/HostKeyAlgorithms/Ciphers/MACs directives in sshd_config) - current OpenSSH defaults already exclude everything this check flags.',
 1.2);
