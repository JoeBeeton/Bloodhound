package org.freedonia.bloodhound.server.apikey;

import java.time.Instant;
import java.util.UUID;

public record ApiKey(
        UUID id,
        UUID organizationId,
        UUID createdByUserId,
        String label,
        String keyPrefix,
        String keyHash,
        Instant createdAt,
        Instant expiresAt,
        Instant lastUsedAt,
        Instant revokedAt) {

    public boolean isActive(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }
}
