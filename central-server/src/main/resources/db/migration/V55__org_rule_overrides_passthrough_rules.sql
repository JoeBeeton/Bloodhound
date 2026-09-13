-- ZAP_ALERT_<pluginId> and NUCLEI_<templateId> findings carry their rule identity through from
-- the scanner (see ZapAlertMapper / NucleiFindingMapper) rather than being seeded into
-- rules_catalog - there are thousands of them and each is self-describing. The cost, found by a
-- rules audit: the FK below meant an org could not disable one. ZAP's "User Agent Fuzzer" was
-- the single largest rule in the findings table and no admin had any switch for it. The
-- override table now accepts any rule id; RulesCatalogController limits writes to catalog ids
-- plus the two pass-through prefixes, and lists the pass-through rules an org has actually
-- seen findings for alongside the catalog so the existing toggle UI covers them.
ALTER TABLE org_rule_overrides DROP CONSTRAINT org_rule_overrides_rule_id_fkey;
