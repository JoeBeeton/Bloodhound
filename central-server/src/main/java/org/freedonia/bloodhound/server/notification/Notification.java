package org.freedonia.bloodhound.server.notification;

import java.time.Instant;
import java.util.UUID;

public record Notification(
        UUID id,
        UUID organizationId,
        String type,
        String severity,
        String title,
        String message,
        UUID targetId,
        String targetHostname,
        UUID scanRunId,
        boolean isRead,
        Instant createdAt) {}
