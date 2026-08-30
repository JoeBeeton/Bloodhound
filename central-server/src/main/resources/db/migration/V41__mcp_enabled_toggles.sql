-- Two independent MCP kill switches, both defaulting to enabled per the user's own choice:
-- an org-wide toggle (an admin can turn MCP off for the whole organization) and a per-user
-- toggle (an admin can disable it for specific users without affecting the rest of the org).
-- Checked at token-issuance/tool-invocation time, not by hiding the OAuth endpoints themselves -
-- see the MCP resource-server wiring.
ALTER TABLE organizations ADD COLUMN mcp_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN mcp_enabled BOOLEAN NOT NULL DEFAULT true;
