package org.freedonia.bloodhound.server.orgs;

import java.time.Instant;
import java.util.UUID;

public record Organization(
        UUID id,
        String name,
        String slug,
        Instant createdAt,
        /** Org-wide MCP kill switch - an admin can turn MCP off for the whole organization; see
         * User#mcpEnabled for the additional per-user override. */
        boolean mcpEnabled) {}
