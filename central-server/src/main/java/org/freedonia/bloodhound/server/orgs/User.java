package org.freedonia.bloodhound.server.orgs;

import java.time.Instant;
import java.util.UUID;

public record User(
        UUID id,
        UUID organizationId,
        String email,
        String displayName,
        String passwordHash,
        String identitySource,
        String role,
        String status,
        Instant createdAt,
        /** Per-user MCP kill switch, on top of the org-wide one (see Organization#mcpEnabled) - an
         * admin can disable MCP access for specific users without affecting the rest of the org. */
        boolean mcpEnabled) {}
