-- EXPOSURE_RABBITMQ_DEFAULT_CREDS: RabbitMQ's management REST API on its default port (15672),
-- probed with its own extremely well-known default credential pair (guest:guest) - the same
-- single well-known-credential pattern this product already established for anonymous FTP login
-- (FtpAnonymousChecker), not a brute-force attempt. Modern RabbitMQ (since 3.3.0) restricts the
-- guest user to localhost connections by default, but real-world deployments routinely re-enable
-- remote guest access or simply never changed the password. Confirmed via a successful
-- authenticated GET /api/whoami (lighter than /api/overview, same auth requirement) - a hardened
-- or default-modern instance rejects the pair with 401. CRITICAL: full management access to
-- queues, exchanges, and messages.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_RABBITMQ_DEFAULT_CREDS', 'EXPOSURE', 'CRITICAL',
 'RabbitMQ management API accepts default credentials',
 'The RabbitMQ management API on its default port (15672) accepted the well-known default credential pair (guest:guest), confirmed via a successful authenticated request. This grants full management access - viewing and manipulating queues, exchanges, and messages - to anyone who tries the default login.',
 'Change the guest user''s password immediately, or delete the guest account and create named administrative accounts instead. Restrict the management port to trusted networks.',
 1.0);
