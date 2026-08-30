package org.freedonia.bloodhound.server.orgs.dto;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.User;

public record UserSummary(
        UUID id,
        String email,
        String displayName,
        String role,
        String status,
        UUID organizationId,
        boolean mcpEnabled,
        String identitySource,
        /** Null if this user has never successfully logged in - see User#lastLoginAt. */
        Instant lastLoginAt) {
    public static UserSummary from(User user) {
        return new UserSummary(
                user.id(),
                user.email(),
                user.displayName(),
                user.role(),
                user.status(),
                user.organizationId(),
                user.mcpEnabled(),
                user.identitySource(),
                user.lastLoginAt());
    }
}
