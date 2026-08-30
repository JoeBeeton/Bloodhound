package org.freedonia.bloodhound.server.auth;

import java.time.Instant;
import java.util.UUID;

public record RefreshToken(
        UUID id,
        UUID userId,
        String tokenHash,
        Instant expiresAt,
        Instant revokedAt,
        Instant createdAt,
        /**
         * Fixed at the moment this token's session/lineage originally began - propagated as-is
         * through every rotation (unlike createdAt, which is fresh per-row) - see
         * AuthenticationService#refresh for the absolute-session-lifetime check this backs.
         */
        Instant sessionStartedAt) {}
