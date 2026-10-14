-- BUCKET_BRUTE_FORCE now also checks Azure Blob Storage (see BucketNameGenerator's
-- generateAzureAccountCandidates and CloudBucketDecisionLogic.Provider.AZURE_BLOB) - closes a gap
-- that class's own javadoc had explicitly flagged as "a real, documented gap, not an oversight"
-- for the passive CNAME-based discovery path (CloudBucketDecisionLogic#matchProvider still
-- correctly excludes Azure there - only brute-force, which doesn't need a CNAME to begin with,
-- gained it). No new rule_id: Azure findings reuse the existing
-- EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC row, same as every other provider this rule
-- already covers - this migration only updates the remediation text to mention it by name.
UPDATE rules_catalog
SET remediation_advice = 'If the bucket belongs to your organization: disable public directory listing (S3: remove public "List objects" grants/bucket policy; GCS: remove allUsers/allAuthenticatedUsers from the bucket''s IAM policy; Azure: disable anonymous public access on the storage account/container; equivalent for DigitalOcean Spaces/Linode/Scaleway). If it does not belong to your organization, no action is needed - this is a coincidental name match.'
WHERE rule_id = 'EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC';
