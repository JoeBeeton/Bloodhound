package org.freedonia.bloodhound.server.audit;

import java.time.Instant;
import java.util.UUID;

public record AuditLogEntry(
        UUID id,
        UUID organizationId,
        UUID actorUserId,
        String actorEmail,
        String action,
        String targetType,
        String targetId,
        String detail,
        Instant createdAt) {}
