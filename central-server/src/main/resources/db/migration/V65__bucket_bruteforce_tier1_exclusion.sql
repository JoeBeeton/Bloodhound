-- Fairness bug found auditing the Compare page's "fair comparison" (Tier-1-only) score: V12
-- introduced emitted_by_tier1 to exclude Tier-2-exclusive rule_ids from the fair score, but
-- EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC (added later, V36) was never added to that
-- exclusion list - it defaulted to TRUE (tier1-eligible) even though BUCKET_BRUTE_FORCE is a
-- Tier 2 module, only ever dispatched via the authorization-gated deep-scan endpoint (see
-- BucketBruteForceModule's own javadoc), exactly the kind of finding a competitor target could
-- never have the chance to accumulate. Without this, an owned target with a brute-forced public
-- bucket scored artificially worse than a competitor in "fair comparison" mode - the same
-- unfairness V12 exists to prevent.
UPDATE rules_catalog
SET emitted_by_tier1 = FALSE
WHERE rule_id = 'EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC';
