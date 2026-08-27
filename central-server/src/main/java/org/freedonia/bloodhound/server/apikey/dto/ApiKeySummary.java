package org.freedonia.bloodhound.server.apikey.dto;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.apikey.ApiKey;

/** Never carries the raw key or its hash - only what's needed to tell keys apart and judge their status in a list. */
public record ApiKeySummary(
        UUID id,
        String label,
        String keyPrefix,
        Instant createdAt,
        Instant expiresAt,
        Instant lastUsedAt,
        boolean revoked,
        boolean expired) {

    public static ApiKeySummary from(ApiKey key, Instant now) {
        return new ApiKeySummary(
                key.id(),
                key.label(),
                key.keyPrefix(),
                key.createdAt(),
                key.expiresAt(),
                key.lastUsedAt(),
                key.revokedAt() != null,
                key.expiresAt().isBefore(now));
    }
}
