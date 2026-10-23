-- Fairness bug found during a rules-parity review (SECURITY_AND_PARITY_REVIEW.md): V73 added
-- NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED as a Tier 2-only rule (it needs a full SSH handshake via
-- zgrab2 against an already-discovered open port 22, dispatched only from DeepPortScanModule) but
-- never added it to the emitted_by_tier1 exclusion list V12/V65 maintain - it defaulted to TRUE
-- (tier1-eligible), the exact same fairness bug V65 already fixed for
-- EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC. Without this, an OWN target that got a deep
-- scan (and so had the chance to accumulate this finding) scored artificially worse in the
-- Compare page's default "fair comparison" (Tier-1-only) mode than a COMPETITOR/WATCHLIST target
-- that never receives Tier 2 scanning at all and so can never have this finding - comparing a
-- target that was looked at harder against one that wasn't, exactly what Tier-1-only mode exists
-- to prevent.
UPDATE rules_catalog
SET emitted_by_tier1 = FALSE
WHERE rule_id = 'NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED';
