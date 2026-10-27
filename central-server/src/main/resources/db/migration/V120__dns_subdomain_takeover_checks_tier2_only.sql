-- A security/legal review of every Tier 1 module found five rules whose underlying checks were
-- never actually passive, despite running unconditionally against every target including
-- COMPETITOR/UNAUTHORIZED ones with no scanning authorization at all:
--   - DNS_ZONE_TRANSFER_ALLOWED / NETWORK_DNS_OPEN_RESOLVER (DnsPostureModule): attempting an
--     AXFR zone transfer, and probing for open recursive resolution, both actively attack the
--     target's own nameserver rather than just reading a DNS record. Moved to the new Tier 2
--     DNS_ZONE_EXPLOIT module - DNS_NS_LAME_DELEGATION stays Tier 1, unaffected.
--   - SUBDOMAIN_DANGLING_CNAME / SUBDOMAIN_NS_DELEGATION_TAKEOVER (SubdomainEnumModule's
--     DanglingCnameChecker/NsTakeoverChecker): an active HTTP GET or direct-to-nameserver DNS
--     query against whatever a discovered subdomain's CNAME or NS records point at. Moved to the
--     new Tier 2 SUBDOMAIN_TAKEOVER_CHECK module - the Katana-crawl-based discovery itself
--     deliberately stays Tier 1.
-- Both new module types are only ever dispatched via TargetController's authorization-gated
-- deep-scan endpoint, same gate as PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN/EXPOSURE_CHECKS/
-- BUCKET_BRUTE_FORCE.
--
-- Flipping emitted_by_tier1 to false for these keeps the "fair comparison" (Tier-1-only) Compare
-- score honest, same reasoning as V12/V65/V117 - a competitor target never gets the chance to
-- accumulate a Tier-2-exclusive finding, so counting one against an owned target that DOES get
-- deep-scanned would be unfair. EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING (the third checker,
-- CloudBucketChecker, also moving to SUBDOMAIN_TAKEOVER_CHECK) already has emitted_by_tier1 =
-- false from V117's blanket EXPOSURE_% update, even though it was still Tier-1-emitted until this
-- migration's code deploys alongside it - no row change needed for it here.
UPDATE rules_catalog
SET emitted_by_tier1 = false
WHERE rule_id IN (
    'DNS_ZONE_TRANSFER_ALLOWED',
    'NETWORK_DNS_OPEN_RESOLVER',
    'SUBDOMAIN_DANGLING_CNAME',
    'SUBDOMAIN_NS_DELEGATION_TAKEOVER'
);
