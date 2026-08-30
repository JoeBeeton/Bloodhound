package org.freedonia.bloodhound.server.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SlackNotifierTest {

    private final SlackNotifier slackNotifier = new SlackNotifier();
    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** A real local listener, not a mock - SlackNotifier's own javadoc calls this out as exactly
     * why {@link SlackNotifier#attemptDelivery} is URL-agnostic: it can be pointed at any HTTP
     * endpoint, not just a genuine Slack webhook. */
    private String startServer(int statusCode) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = statusCode == 200 ? "ok".getBytes() : "error".getBytes();
            exchange.sendResponseHeaders(statusCode, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/";
    }

    @Test
    void attemptDelivery_200Response_reportedAsSuccess() throws IOException {
        String url = startServer(200);

        SlackNotifier.DeliveryResult result = slackNotifier.attemptDelivery(url, "Title", "msg", "INFO", "https://app/x");

        assertThat(result.success()).isTrue();
        assertThat(result.detail()).isNull();
    }

    @Test
    void attemptDelivery_non200Response_reportedAsFailureWithStatusInDetail() throws IOException {
        String url = startServer(404);

        SlackNotifier.DeliveryResult result = slackNotifier.attemptDelivery(url, "Title", "msg", "INFO", "https://app/x");

        assertThat(result.success()).isFalse();
        assertThat(result.detail()).contains("404");
    }

    @Test
    void attemptDelivery_unreachableHost_reportedAsFailureWithExceptionDetail_doesNotThrow() throws IOException {
        // Bind a real local port, then stop the server before calling it - a reliably-refused
        // connection on loopback, unlike guessing at a low/blocked port number, which can behave
        // unpredictably (hang vs. immediately refuse) depending on the sandbox's network policy.
        // The whole point is that a network failure comes back as a DeliveryResult, not an
        // exception the caller (the test-send endpoint) has to catch.
        String url = startServer(200);
        server.stop(0);

        SlackNotifier.DeliveryResult result = slackNotifier.attemptDelivery(url, "Title", "msg", "INFO", "https://app/x");

        assertThat(result.success()).isFalse();
        assertThat(result.detail()).isNotBlank();
    }

    @Test
    void criticalSeverityUsesMagentaAccent() {
        String payload = SlackNotifier.buildPayload("New findings", "3 new criticals", "CRITICAL", "https://app/x");
        assertTrue(payload.contains("#ff2e97"));
    }

    @Test
    void mediumSeverityUsesAmberAccent() {
        String payload = SlackNotifier.buildPayload("New findings", "1 new medium", "MEDIUM", "https://app/x");
        assertTrue(payload.contains("#ffb800"));
    }

    @Test
    void infoSeverityUsesCyanAccent() {
        String payload = SlackNotifier.buildPayload("Scan started", "…", "INFO", "https://app/x");
        assertTrue(payload.contains("#00f0ff"));
    }

    @Test
    void escapesQuotesAndNewlinesInMessage() {
        String payload = SlackNotifier.buildPayload("Title", "line1\nwith \"quotes\"", "INFO", "https://app/x");
        assertTrue(payload.contains("line1\\nwith \\\"quotes\\\""));
    }

    @Test
    void includesLinkUrl() {
        String payload = SlackNotifier.buildPayload("Title", "msg", "INFO", "https://app.example/targets/abc");
        assertTrue(payload.contains("https://app.example/targets/abc"));
    }

    @Test
    void slackLinkSyntaxInFindingText_neutralized_notRenderedAsALiveLink() {
        // Real phishing vector, found by a security review: attacker-controlled finding text
        // (a hostile scan target's own page title, WHOIS text, etc.) containing Slack's own
        // <url|text> link syntax must not survive into the payload verbatim, or it renders as a
        // real clickable link in the analyst's Slack channel.
        String payload = SlackNotifier.buildPayload(
                "Title", "<http://evil.example|Click here>", "INFO", "https://app.example/x");
        assertTrue(payload.contains("&lt;http://evil.example|Click here&gt;"));
        assertFalse(payload.contains("<http://evil.example|Click here>"));
    }

    @Test
    void ampersand_escapedOnce_notDoubleEscaped() {
        String payload = SlackNotifier.buildPayload("Title", "Q&A page found", "INFO", "https://app.example/x");
        assertTrue(payload.contains("Q&amp;A page found"));
        assertFalse(payload.contains("&amp;amp;"));
    }
}
