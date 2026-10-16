-- APP_STORE_MONITOR: closes a real gap in this product's brand-protection coverage - the existing
-- typosquat module covers the domain-level phishing/impersonation channel, but had no equivalent
-- for the app-store channel at all, a genuine category commercial brand-protection platforms
-- (e.g. Unphish) cover separately. Searches Apple's official iTunes Search API and Google Play's
-- own search page (see GooglePlayClient's own javadoc on that fragility tradeoff) for the target's
-- brand name, flagging listings whose developer name doesn't itself contain the brand - verified
-- live before building: a real search for "example finance" surfaced both the real company's own
-- correctly-silent apps (developer "Example Finance Ltd") and a genuinely suspicious third result
-- ("EXAMPLE Finance Tracker" by an unrelated individual developer).
--
-- MEDIUM, not HIGH/CRITICAL: this is a heuristic with real false-positive potential (an unofficial
-- fan app or review tool can legitimately mention a brand by name without being malicious) - same
-- "worth a human look, not proof" tier as TLS_CT_UNEXPECTED_ISSUER.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('BRAND_IMPERSONATING_APP_DETECTED', 'BRAND', 'MEDIUM',
 'Possible brand-impersonating app found on an app store',
 'An app on the Apple App Store or Google Play mentions this organization''s brand name in its title, but is published under a developer name that doesn''t itself contain the brand - unlike this organization''s own real app listings. This can be a legitimate unofficial fan app or review tool, but is also a pattern seen with fake banking/finance apps designed to phish credentials or card details.',
 'Review the app listing directly. If it is impersonating your brand or app, report it to the relevant app store''s abuse/trademark-infringement reporting process for takedown.',
 0.8);
