-- Milestone 6b: dangling-CNAME/subdomain-takeover detection. No table
-- changes needed - subdomains.dangling_cname_target has existed unused since
-- Milestone 4/5's migration, reserved for exactly this. Only a new
-- rules_catalog entry is required.

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('SUBDOMAIN_DANGLING_CNAME', 'SUBDOMAIN_HYGIENE', 'CRITICAL',
 'Dangling CNAME - possible subdomain takeover',
 'This subdomain has a CNAME record pointing to a third-party service (e.g. S3, GitHub Pages, Heroku, Azure, Zendesk, Shopify, or Fastly) resource that appears to be unclaimed. An attacker who registers the same resource name on that service can serve arbitrary content from this subdomain.',
 'Either remove the stale CNAME record if the resource is no longer needed, or immediately re-claim the corresponding resource on the third-party service to prevent takeover.', 2.0);
