package org.freedonia.bloodhound.worker.modules.nuclei;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure parse of nuclei's {@code -jsonl} stdout output (one JSON object per
 * matched result, one per line) into {@link NucleiFinding} records. No
 * process/network work here - see {@link NucleiFetcher} - so this is
 * unit-testable against canned response fixtures.
 *
 * <p>Confirmed against nuclei's real output shape (v3.11.1, live run) rather
 * than assumed from docs alone - field names below (including the hyphenated
 * top-level ones like {@code template-id}/{@code matched-at}) match exactly
 * what the binary actually emits.
 */
public final class NucleiResultParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private NucleiResultParser() {}

    public static List<NucleiFinding> parse(String jsonl) {
        List<NucleiFinding> results = new ArrayList<>();
        if (jsonl == null || jsonl.isBlank()) {
            return results;
        }
        for (String line : jsonl.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            JsonNode node;
            try {
                node = MAPPER.readTree(trimmed);
            } catch (Exception e) {
                // A stray non-JSON line (banner text, a warning nuclei printed despite -silent) -
                // skip it defensively rather than failing the whole scan over one bad line.
                continue;
            }
            JsonNode info = node.path("info");
            results.add(new NucleiFinding(
                    text(node, "template-id"),
                    text(info, "name"),
                    text(info, "severity"),
                    text(info, "description"),
                    text(node, "host"),
                    text(node, "matched-at"),
                    joinArray(info.path("reference")),
                    toStringList(node.path("extracted-results")),
                    text(node, "curl-command"),
                    text(info.path("classification"), "cve-id")));
        }
        return results;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String joinArray(JsonNode arrayNode) {
        if (arrayNode == null || !arrayNode.isArray() || arrayNode.isEmpty()) {
            return null;
        }
        List<String> values = toStringList(arrayNode);
        return String.join(", ", values);
    }

    private static List<String> toStringList(JsonNode arrayNode) {
        List<String> values = new ArrayList<>();
        if (arrayNode != null && arrayNode.isArray()) {
            for (JsonNode item : arrayNode) {
                if (!item.isNull()) {
                    values.add(item.asText());
                }
            }
        }
        return values;
    }
}
