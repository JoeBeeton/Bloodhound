package org.freedonia.bloodhound.server.notification;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record SlackIntegration(
        UUID id,
        UUID organizationId,
        String webhookUrl,
        boolean enabled,
        List<String> notificationTypes,
        /** When true, Slack delivery is further restricted to notifications about OWN-type
         * targets (in addition to the notificationTypes filter above) - in-app notifications
         * are unaffected, this only narrows what gets sent to Slack. */
        boolean ownTargetsOnly,
        Instant createdAt,
        Instant updatedAt) {}
