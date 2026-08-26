-- Typosquat/lookalike-domain brand-protection monitoring (Tier 1,
-- competitive-research-recommended: the clearest actual feature-parity gap
-- against mature commercial ASM tools, several of which treat this as a
-- mature, expected capability that Bloodhound had zero coverage of before
-- this).
--
-- Current-state-per-candidate table (upserted on every rescan, is_registered
-- flips as domains get registered/expire), not append-only history - same
-- rationale as fingerprints. Registration status alone is the actionable
-- signal (proving live phishing content is a separate, paid-tooling-
-- dependent capability, deliberately out of scope here).
CREATE TABLE typosquat_candidates (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id         UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    candidate_domain  TEXT NOT NULL,
    permutation_type  TEXT NOT NULL,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_registered     BOOLEAN NOT NULL DEFAULT false,
    resolved_ip       TEXT,
    registration_date TIMESTAMPTZ,
    UNIQUE (target_id, candidate_domain)
);

CREATE INDEX idx_typosquat_candidates_target ON typosquat_candidates (target_id);

-- BRAND is deliberately outside ScoringEngine's fixed 6-category weight
-- table, same precedent as WHOIS/BREACH/WEB_APP: shows up in findings/UI,
-- never affects the score (a lookalike domain isn't a fact about the
-- target's own infrastructure posture).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('TYPOSQUAT_DOMAIN_REGISTERED', 'BRAND', 'HIGH',
 'Registered lookalike domain detected',
 'A domain closely resembling this target''s own - generated via common typosquatting techniques (character omission/duplication/transposition, keyboard-adjacent substitution, homoglyph substitution, TLD swap, or hyphenation) - is registered and actively resolving. This is consistent with phishing or brand-impersonation infrastructure, though it can occasionally be a coincidentally similarly-named, unrelated legitimate site.',
 'Investigate the flagged domain to confirm whether it is malicious. If so, consider reporting it to the registrar/host, pursuing a UDRP proceeding, or blocking it at your organization''s email/web gateways.',
 1.0);
