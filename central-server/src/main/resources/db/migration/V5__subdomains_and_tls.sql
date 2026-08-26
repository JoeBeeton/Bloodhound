-- Milestone 4: discovered subdomains + rules_catalog seed rows for the two
-- new Tier 1 modules (TLS analysis, subdomain enumeration). No schema change
-- needed for findings/scan_jobs - both new modules produce ordinary
-- RawFindings through the existing pipeline (see ResultIngestionService for
-- the one SUBDOMAIN_ENUM-specific branch that also upserts this table).

CREATE TABLE subdomains (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id              UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    hostname               TEXT NOT NULL,
    first_seen_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    source                 TEXT NOT NULL,
    is_active              BOOLEAN NOT NULL DEFAULT TRUE,
    current_ip_addresses   JSONB,
    -- Populated by Milestone 6's dangling-CNAME/takeover detection - the
    -- column exists now per the plan's schema so that milestone needs no
    -- migration, nothing writes to it yet.
    dangling_cname_target  TEXT,
    CONSTRAINT uq_subdomains_target_hostname UNIQUE (target_id, hostname)
);

CREATE INDEX idx_subdomains_target_id ON subdomains(target_id);

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('SUBDOMAIN_NEW_UNEXPECTED', 'SUBDOMAIN_HYGIENE', 'INFO',
 'New subdomain discovered',
 'A subdomain not previously observed for this target was discovered via certificate-transparency-based enumeration.',
 'Confirm this subdomain is expected and intentionally exposed; decommission it if it is not.', 0.5),
('TLS_CERT_EXPIRED', 'TLS', 'CRITICAL',
 'TLS certificate expired',
 'The certificate presented for this host has already expired, so browsers and clients will reject or warn on every connection.',
 'Renew and deploy a new certificate immediately.', 1.5),
('TLS_CERT_EXPIRING_SOON', 'TLS', 'MEDIUM',
 'TLS certificate expiring soon',
 'The certificate presented for this host expires within 30 days.',
 'Renew the certificate before expiry; consider automated renewal (e.g. ACME/Let''s Encrypt) to prevent recurrence.', 1.0),
('TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN', 'TLS', 'HIGH',
 'Untrusted or self-signed TLS certificate chain',
 'The certificate chain presented for this host does not validate against a public trust root.',
 'Deploy a certificate issued by a publicly trusted Certificate Authority.', 1.2),
('TLS_WEAK_PROTOCOL_SUPPORTED', 'TLS', 'HIGH',
 'Legacy TLS protocol supported',
 'The server accepted a handshake using a deprecated TLS protocol version (TLSv1 or TLSv1.1), both retired by major browsers and PCI-DSS.',
 'Disable TLSv1 and TLSv1.1 on the server, allowing only TLSv1.2 and TLSv1.3.', 1.2),
('TLS_WEAK_CIPHER_SUITE', 'TLS', 'MEDIUM',
 'Weak TLS cipher suite negotiated',
 'The server negotiated a cipher suite using a known-weak algorithm (e.g. RC4, DES/3DES, NULL, EXPORT, or MD5).',
 'Reconfigure the server''s cipher suite preference list to exclude weak/legacy ciphers.', 1.0),
('TLS_NO_HSTS', 'TLS', 'MEDIUM',
 'Missing HSTS header',
 'The response has no Strict-Transport-Security header, so browsers will not enforce HTTPS-only connections for this host.',
 'Add a Strict-Transport-Security header with a long max-age and includeSubDomains.', 1.0),
('TLS_HSTS_SHORT_MAX_AGE', 'TLS', 'LOW',
 'Weak HSTS policy',
 'A Strict-Transport-Security header is present but its max-age is under 6 months and/or it is missing includeSubDomains.',
 'Set max-age to at least 15552000 (6 months, ideally 31536000/1 year) and include includeSubDomains.', 0.7);
