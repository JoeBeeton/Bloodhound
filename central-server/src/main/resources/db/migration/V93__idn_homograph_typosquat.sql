-- Widened PermutationGenerator (worker) to also generate IDN/Unicode homograph candidates - a
-- real, distinct phishing technique (e.g. registering the domain that *renders* as "аpple.com"
-- using Cyrillic а instead of Latin a, actually stored/resolved as "xn--pple-43d.com") this
-- module's prior ASCII-only homoglyph generation (o/0, l/1, s/5, e/3, a/4, m/rn) never covered.
-- Reuses the existing TYPOSQUAT_DOMAIN_REGISTERED/BRAND_TYPOSQUAT_MX_CONFIGURED/
-- BRAND_TYPOSQUAT_HOSTING_LIVE_SITE rules and their whole detection pipeline unchanged - no new
-- rule_id needed, same pattern as V90's port-set widening. Description-text update only, so the
-- technique list stays accurate.
UPDATE rules_catalog
SET description = 'A domain closely resembling this target''s own - generated via common typosquatting techniques (character omission/duplication/transposition, keyboard-adjacent substitution, ASCII homoglyph substitution, cross-script IDN/Unicode homograph substitution, TLD swap, or hyphenation) - is registered and actively resolving. This is consistent with phishing or brand-impersonation infrastructure, though it can occasionally be a coincidentally similarly-named, unrelated legitimate site.'
WHERE rule_id = 'TYPOSQUAT_DOMAIN_REGISTERED';
