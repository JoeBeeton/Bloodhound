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
        Instant createdAt,
        /** Free-text context an analyst leaves on a target (which environment, who owns it, why it's tracked) - absent for every target created before V45__target_notes.sql. */
        String notes) {}
