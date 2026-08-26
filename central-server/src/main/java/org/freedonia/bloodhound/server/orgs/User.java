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
        Instant createdAt) {}
