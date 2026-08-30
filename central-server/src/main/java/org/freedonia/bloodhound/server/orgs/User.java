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
        boolean mcpEnabled,
        /** Null until their first successful login - written by UserRepository#touchLastLogin on
         * every LOCAL and SAML sign-in, but a product/AppSec review found nothing anywhere ever
         * read it back: dormant/never-used accounts (an SSO/SCIM-provisioned user who was granted
         * access but never actually signed in, or an old account nobody remembered to disable)
         * were completely invisible to an admin auditing who actually has access. */
        Instant lastLoginAt) {}
