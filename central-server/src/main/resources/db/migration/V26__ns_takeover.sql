-- NS-delegation subdomain takeover - distinct from both SUBDOMAIN_DANGLING_CNAME
-- (a subdomain CNAME'd to an unclaimed *resource*) and
-- EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING (a claimed bucket that's publicly
-- readable). This is a subdomain delegated as its own independent DNS zone
-- (NS records, not CNAME) to a cloud DNS provider whose corresponding hosted
-- zone has been deprovisioned - whoever notices can claim it and become fully
-- authoritative for the subdomain, every record type, not just one HTTP
-- response. Distinct from DNS_NS_LAME_DELEGATION (apex-only, any lame
-- nameserver): this fires specifically when the lame nameserver is a known
-- cloud DNS provider, which is what makes it attacker-claimable rather than
-- just misconfigured.

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('SUBDOMAIN_NS_DELEGATION_TAKEOVER', 'SUBDOMAIN_HYGIENE', 'CRITICAL',
 'Dangling NS delegation - possible subdomain takeover',
 'This subdomain is delegated (via NS records) to a cloud DNS provider''s nameservers, but no hosted zone answers authoritatively for it there - the delegation appears to point at a deprovisioned or never-created zone. Anyone who notices can create a matching zone at that provider and become fully authoritative for this subdomain, including mail (MX) and any other record type - not just a single HTTP response like a dangling CNAME.',
 'Remove the dangling NS delegation from this domain''s DNS if the zone is no longer needed, or immediately recreate the hosted zone at the provider to reclaim it.',
 2.0);
