package org.freedonia.bloodhound.server.target;

import java.time.Instant;
import java.util.UUID;

public record Target(
        UUID id,
        UUID organizationId,
        String hostname,
        String targetType,
        String authorizationStatus,
        int scanCadenceSeconds,
        Instant nextScanAt,
        boolean isActive,
        Instant createdAt) {}
