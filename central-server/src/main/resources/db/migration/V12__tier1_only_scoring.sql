-- Fairness fix: Tier 2 (deep port scan, ZAP active scan) only ever runs against
-- explicitly-authorized targets, which in practice means a user's own
-- domains, since nobody authorizes active scanning against a competitor's
-- infrastructure. Without this, an owned target accumulates Tier
-- 2-exclusive findings a competitor target never gets the chance to have
-- discovered against it, making /compare fundamentally unfair. This adds a
-- second, Tier-1-only score alongside the existing full score.

ALTER TABLE rules_catalog
    ADD COLUMN emitted_by_tier1 BOOLEAN NOT NULL DEFAULT TRUE;

-- The only two rule_ids that can *only* ever come from a Tier 2 module:
-- NETWORK_ANONYMOUS_FTP (anonymous-login probe, deep scan only) and
-- NETWORK_FULL_PORT_SURFACE (a full 65535-port summary, deep scan only).
-- PORT_UNEXPECTED_OPEN_ADMIN_SERVICE and PORT_OPEN_UNENCRYPTED_MGMT are
-- deliberately NOT marked false here - DeepPortScanDecisionLogic reuses
-- those exact rule_ids (with richer evidence) for ports a Tier 1 light scan
-- could equally well have found on its own, so excluding them would
-- under-count what a Tier-1-only scan is genuinely capable of finding.
UPDATE rules_catalog
SET emitted_by_tier1 = FALSE
WHERE rule_id IN ('NETWORK_ANONYMOUS_FTP', 'NETWORK_FULL_PORT_SURFACE');

-- Additive columns alongside the existing overall_score/grade/category_scores,
-- which continue to represent the full score unchanged. Nullable: existing
-- historical snapshots predate this fix and have no Tier-1-only figure.
ALTER TABLE score_snapshots
    ADD COLUMN tier1_overall_score NUMERIC(5, 2),
    ADD COLUMN tier1_grade CHAR(1),
    ADD COLUMN tier1_category_scores JSONB;
