-- DNS_DMARC_SUBDOMAIN_POLICY_WEAKER: closes a gap the existing DMARC checks never covered - the
-- sp= (subdomain policy, RFC 7489 6.3) tag, which overrides p= specifically for subdomains. sp=
-- being absent is not a gap at all (p= already applies to subdomains too, per spec default) - the
-- real finding is an sp= EXPLICITLY set weaker than the domain's own p= (e.g. p=reject but
-- sp=none), carving out a lower enforcement bar for every subdomain. Spoofed mail appearing to
-- come from any subdomain then gets less protection than mail from the apex domain itself. May be
-- intentional (subdomains known not to send mail) or a forgotten leftover from testing - either
-- way, worth a human look, the same framing DNS_DMARC_POLICY_NONE already uses for p=none itself.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('DNS_DMARC_SUBDOMAIN_POLICY_WEAKER', 'DNS', 'MEDIUM',
 'DMARC subdomain policy weaker than the domain''s own policy',
 'This DMARC record''s sp= (subdomain policy) tag is explicitly set weaker than its own p= policy (e.g. p=reject but sp=none), carving out a lower enforcement bar for every subdomain. Spoofed mail appearing to come from any subdomain gets less protection than mail from the apex domain itself.',
 'Remove the sp= tag entirely (so p= applies uniformly to subdomains too), or set it to match or exceed the strength of p=, unless subdomains are confirmed never to send mail and a lower bar is genuinely intentional.',
 0.4);
