-- A security review found RulesCatalogController's PATCH endpoint updated the global
-- rules_catalog.enabled column with no organization scoping at all - any org's ADMIN could
-- disable a detection rule (e.g. TLS_EXPIRED) for every other tenant, since ResultIngestionService
-- filtered ingestion by that same global flag. This overlay table makes a rule's enabled state
-- per-org: a row here overrides rules_catalog.enabled for that (org, rule) pair; no row means the
-- rule's shipped default (rules_catalog.enabled, no longer directly writable via the API) applies.
CREATE TABLE org_rule_overrides (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL REFERENCES rules_catalog(rule_id) ON DELETE CASCADE,
    enabled         BOOLEAN NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, rule_id)
);
