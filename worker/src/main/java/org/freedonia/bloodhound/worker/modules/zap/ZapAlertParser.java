package org.freedonia.bloodhound.worker.modules.zap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure parse of ZAP's /JSON/core/view/alerts/ response into {@link ZapAlert}
 * records. No network work here - see {@link ZapScanRunner} - so this is
 * unit-testable against canned response fixtures.
 */
public final class ZapAlertParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ZapAlertParser() {}

    public static List<ZapAlert> parse(String alertsJson) {
        List<ZapAlert> alerts = new ArrayList<>();
        JsonNode root;
        try {
            root = MAPPER.readTree(alertsJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("failed to parse ZAP alerts response", e);
        }
        for (JsonNode node : root.path("alerts")) {
            // ZAP's alert object uses "alert" for the display name; some
            // versions/views also expose "name" as an alias - prefer "name"
            // if present, fall back to "alert".
            String name = text(node, "name");
            if (name == null || name.isBlank()) {
                name = text(node, "alert");
            }
            alerts.add(new ZapAlert(
                    text(node, "pluginId"),
                    name,
                    text(node, "risk"),
                    text(node, "confidence"),
                    text(node, "description"),
                    text(node, "solution"),
                    text(node, "reference"),
                    text(node, "url"),
                    text(node, "param"),
                    text(node, "evidence"),
                    text(node, "other")));
        }
        return alerts;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }
}
