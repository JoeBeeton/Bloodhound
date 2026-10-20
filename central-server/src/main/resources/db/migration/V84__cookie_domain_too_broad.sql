-- COOKIE_DOMAIN_TOO_BROAD: closes a gap in the existing cookie-hardening checks (Secure,
-- HttpOnly, SameSite, __Host-/__Secure- prefix were all covered, but never the Domain attribute's
-- own scope). No Domain attribute at all is the safest default (RFC 6265 host-only cookie); an
-- explicit Domain set to a PARENT of the host that set it broadens the cookie to every subdomain -
-- the same subdomains this product's own SUBDOMAIN_DANGLING_CNAME/SUBDOMAIN_NS_DELEGATION_TAKEOVER
-- checks already flag as a real attacker foothold risk. A cookie scoped this broadly is sent to
-- (and, without HttpOnly, readable by script on) any one of them, including one since abandoned
-- or retaken over. LOW: a scope/attack-surface issue, not a direct removal of a security control
-- like Secure/HttpOnly.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('COOKIE_DOMAIN_TOO_BROAD', 'HEADERS', 'LOW',
 'Cookie scoped to a parent domain, not just this host',
 'A cookie sets its Domain attribute to a parent of the host that set it, broadening the cookie''s scope to every subdomain rather than just this one (the default, safer behavior when Domain is left out entirely). The cookie is sent to - and, without HttpOnly, readable by script running on - any one of those subdomains, including one that has since been abandoned or taken over.',
 'Remove the Domain attribute entirely (the cookie will then default to host-only scope), or set it to the exact host rather than a parent domain, unless the cookie genuinely needs to be shared across subdomains.',
 0.3);
