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
        attemptDelivery(webhookUrl, title, message, severity, linkUrl);
    }

    /** Whether delivery reached Slack with a 200, and - if not - enough detail to act on (a bad
     * URL, a revoked webhook, a network failure) without digging through server logs. */
    public record DeliveryResult(boolean success, String detail) {
        static DeliveryResult ok() {
            return new DeliveryResult(true, null);
        }

        static DeliveryResult failed(String detail) {
            return new DeliveryResult(false, detail);
        }
    }

    /**
     * The synchronous core {@link #send} fires-and-forgets on the async executor - split out so
     * SlackIntegrationController's "send a test message" endpoint can call it directly and return
     * the real outcome to whoever clicked the button, instead of the silent server-log-only
     * failure path every other caller of this class gets (acceptable there since the in-app
     * notification is the source of truth regardless, but not for a deliberate "does this even
     * work" check - an admin who fat-fingers a webhook URL deserves to find out immediately, not
     * by waiting for the next real alert that never arrives).
     */
    DeliveryResult attemptDelivery(String webhookUrl, String title, String message, String severity, String linkUrl) {
        String payload = buildPayload(title, message, severity, linkUrl);
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(webhookUrl))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return DeliveryResult.ok();
            }
            log.warn("Slack webhook delivery failed: HTTP {} - {}", response.statusCode(), response.body());
            return DeliveryResult.failed("Slack responded with HTTP " + response.statusCode());
        } catch (Exception e) {
            log.warn("Slack webhook delivery failed: {}", e.toString());
            return DeliveryResult.failed(e.getClass().getSimpleName() + ": " + e.getMessage());
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
