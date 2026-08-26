package org.freedonia.bloodhound.server.notification;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Delivers one Slack message. Deliberately does NOT validate the URL is a real
 * hooks.slack.com address itself - that's enforced once, at config-write time, by
 * SlackIntegrationController (see SlackWebhookValidator). Keeping this class itself
 * URL-agnostic is what lets it be unit/integration-tested directly against any HTTP
 * endpoint (e.g. a local test listener) without weakening the real validation the
 * shipped config-write path enforces.
 *
 * <p>{@code @Async} (enabled via ServerApplication's {@code @EnableAsync}): a slow or
 * unreachable Slack endpoint must never delay or fail the scan/finding pipeline that
 * triggered the notification. One best-effort attempt per message, no retry/backoff -
 * a dropped Slack message is a real but acceptable gap for this feature's scope; the
 * in-app notification (NotificationRepository) is the source of truth regardless.
 */
@Component
public class SlackNotifier {

    private static final Logger log = LoggerFactory.getLogger(SlackNotifier.class);

    private final HttpClient httpClient =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Async
    public void send(String webhookUrl, String title, String message, String severity, String linkUrl) {
        String payload = buildPayload(title, message, severity, linkUrl);
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(webhookUrl))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("Slack webhook delivery failed: HTTP {} - {}", response.statusCode(), response.body());
            }
        } catch (Exception e) {
            log.warn("Slack webhook delivery failed: {}", e.toString());
        }
    }

    /** Pure - split out from {@link #send} so message formatting is unit-testable without a real HTTP call. */
    static String buildPayload(String title, String message, String severity, String linkUrl) {
        String color =
                switch (severity) {
                    case "CRITICAL", "HIGH" -> "#ff2e97";
                    case "MEDIUM" -> "#ffb800";
                    default -> "#00f0ff";
                };
        return """
                {"attachments":[{"color":"%s","title":"%s","text":"%s","title_link":"%s","footer":"Bloodhound"}]}"""
                .formatted(color, jsonEscape(title), jsonEscape(message), jsonEscape(linkUrl));
    }

    private static String jsonEscape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
