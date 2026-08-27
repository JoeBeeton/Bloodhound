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

    /**
     * Neutralizes Slack's own mrkdwn special characters, then JSON-escapes for the payload
     * itself - a security review found the JSON escaping alone (backslash/quote/newline) left
     * Slack's link syntax live: attacker-controlled finding text (a hostile scan target's own
     * page title, WHOIS text, TLS field, etc. - all of which flow into notification title/message
     * unescaped-by-source, same as any other evidence string in this codebase) containing
     * {@code <http://evil.example|Click here>} would render as a real clickable link in the
     * analyst's Slack channel - a phishing vector aimed at the person monitoring alerts. Slack's
     * own documented escaping order matters: {@code &} first, then {@code <}/{@code >} - escaping
     * the angle brackets first would have the {@code &} replacement re-escape the {@code &amp;}
     * it just introduced.
     */
    private static String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n");
    }
}
