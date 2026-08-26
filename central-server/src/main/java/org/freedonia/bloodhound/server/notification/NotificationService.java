package org.freedonia.bloodhound.server.notification;

import java.util.UUID;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The single place that creates a notification AND (if the org has Slack configured
 * and enabled for that type) fires delivery - two sinks for the same event, not two
 * separate code paths scattered across the scan/finding pipeline. Callers (ScanRunService)
 * don't know or care whether Slack is configured; they just report "this happened."
 */
@Service
public class NotificationService {

    private final NotificationRepository notificationRepository;
    private final SlackIntegrationRepository slackIntegrationRepository;
    private final SlackNotifier slackNotifier;
    private final TargetRepository targetRepository;
    private final String appBaseUrl;

    public NotificationService(
            NotificationRepository notificationRepository,
            SlackIntegrationRepository slackIntegrationRepository,
            SlackNotifier slackNotifier,
            TargetRepository targetRepository,
            @Value("${bloodhound.notifications.app-base-url}") String appBaseUrl) {
        this.notificationRepository = notificationRepository;
        this.slackIntegrationRepository = slackIntegrationRepository;
        this.slackNotifier = slackNotifier;
        this.targetRepository = targetRepository;
        this.appBaseUrl = appBaseUrl;
    }

    public void notify(
            UUID organizationId,
            NotificationType type,
            String severity,
            String title,
            String message,
            UUID targetId,
            UUID scanRunId) {
        notificationRepository.insert(organizationId, type.name(), severity, title, message, targetId, scanRunId);

        slackIntegrationRepository.findByOrganization(organizationId).ifPresent(integration -> {
            if (!integration.enabled() || !integration.notificationTypes().contains(type.name())) {
                return;
            }
            if (integration.ownTargetsOnly() && !isOwnTarget(targetId)) {
                return;
            }
            String link = targetId != null ? appBaseUrl + "/targets/" + targetId : appBaseUrl + "/dashboard";
            slackNotifier.send(integration.webhookUrl(), title, message, severity, link);
        });
    }

    /** No target (a rare, org-wide event) can't be "owned", so the ownTargetsOnly filter -
     * an opt-in restriction - conservatively excludes it rather than letting it bypass the filter. */
    private boolean isOwnTarget(UUID targetId) {
        if (targetId == null) {
            return false;
        }
        return targetRepository.findById(targetId).map(t -> "OWN".equals(t.targetType())).orElse(false);
    }
}
