package org.freedonia.bloodhound.server.notification;

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
}
