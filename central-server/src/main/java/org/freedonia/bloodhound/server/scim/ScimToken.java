package org.freedonia.bloodhound.server.scim;

import java.time.Instant;
import java.util.UUID;

public record ScimToken(
        UUID id,
        UUID organizationId,
        String label,
        String tokenHash,
        Instant createdAt,
        Instant revokedAt,
        /** Null means it never expires - see V44__scim_token_expiry.sql for why that's the default. */
        Instant expiresAt) {

    public boolean isActive(Instant now) {
        return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
    }
}
