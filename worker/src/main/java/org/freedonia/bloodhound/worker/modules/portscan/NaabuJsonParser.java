package org.freedonia.bloodhound.worker.modules.portscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Pure parse of naabu's {@code -json -silent} output (one JSON object per
 * open port found, e.g. {@code {"ip":"1.2.3.4","port":443,"protocol":"tcp",
 * "tls":false,"timestamp":"..."}}) into a deduplicated, sorted port list -
 * no process invocation, fully unit-testable against canned output.
 *
 * <p>Deduplication matters here: naabu retries each port up to
 * {@code -retries} times and emits one line per successful probe, so a port
 * that answered on every retry appears more than once in the raw output.
 */
public final class NaabuJsonParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private NaabuJsonParser() {}

    public static List<Integer> parseOpenPorts(String jsonLines) {
        if (jsonLines == null || jsonLines.isBlank()) {
            return List.of();
        }
        SortedSet<Integer> ports = new TreeSet<>();
        for (String line : jsonLines.split("\\r?\\n")) {
            if (line.isBlank()) {
                continue;
            }
            try {
                JsonNode node = MAPPER.readTree(line);
                if (node.has("port")) {
                    ports.add(node.get("port").asInt());
                }
            } catch (Exception e) {
                // naabu occasionally emits a non-JSON status line even with -silent - skip it.
            }
        }
        return new ArrayList<>(ports);
    }
}
