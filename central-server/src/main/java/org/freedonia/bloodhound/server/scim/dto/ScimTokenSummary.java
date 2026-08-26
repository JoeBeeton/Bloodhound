package org.freedonia.bloodhound.server.scim.dto;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.scim.ScimToken;

/** Never carries the token value itself - only shown once, at creation. */
public record ScimTokenSummary(UUID id, String label, Instant createdAt, Instant revokedAt) {

    public static ScimTokenSummary from(ScimToken token) {
        return new ScimTokenSummary(token.id(), token.label(), token.createdAt(), token.revokedAt());
    }
}
