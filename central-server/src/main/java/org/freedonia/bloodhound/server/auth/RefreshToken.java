package org.freedonia.bloodhound.server.auth;

import java.time.Instant;
import java.util.UUID;

public record RefreshToken(
        UUID id, UUID userId, String tokenHash, Instant expiresAt, Instant revokedAt, Instant createdAt) {}
