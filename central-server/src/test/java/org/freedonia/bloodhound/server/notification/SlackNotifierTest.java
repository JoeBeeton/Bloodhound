package org.freedonia.bloodhound.server.notification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SlackNotifierTest {

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
