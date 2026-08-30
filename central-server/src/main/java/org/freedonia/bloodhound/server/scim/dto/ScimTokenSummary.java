package org.freedonia.bloodhound.server.scim.dto;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.scim.ScimToken;

/** Never carries the token value itself - only shown once, at creation. */
public record ScimTokenSummary(
        UUID id,
        String label,
        Instant createdAt,
        Instant revokedAt,
        /** Null means it never expires. */
        Instant expiresAt,
        boolean expired) {

    public static ScimTokenSummary from(ScimToken token) {
        Instant now = Instant.now();
        return new ScimTokenSummary(
                token.id(),
                token.label(),
                token.createdAt(),
                token.revokedAt(),
                token.expiresAt(),
                token.expiresAt() != null && token.expiresAt().isBefore(now));
    }
}
