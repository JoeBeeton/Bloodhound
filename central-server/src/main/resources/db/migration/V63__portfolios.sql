-- Lets a user group several targets (e.g. example.co.uk + example.finance) into one blended-score
-- view while every member target's own scans/findings/subdomains stay completely independent -
-- see PortfolioService for the blend itself. Single nullable FK, not a join table: nothing in
-- the ask implies a target needs to belong to more than one portfolio at once, and this makes
-- "move a target between portfolios" a plain UPDATE instead of a delete+insert.
CREATE TABLE portfolios (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_portfolios_org_name UNIQUE (organization_id, name)
);

CREATE INDEX idx_portfolios_organization_id ON portfolios(organization_id);

-- ON DELETE SET NULL, not CASCADE: deleting a portfolio un-groups its member targets, it must
-- never delete the targets themselves (or their scan/finding history).
ALTER TABLE targets ADD COLUMN portfolio_id UUID REFERENCES portfolios(id) ON DELETE SET NULL;

CREATE INDEX idx_targets_portfolio_id ON targets(portfolio_id);
