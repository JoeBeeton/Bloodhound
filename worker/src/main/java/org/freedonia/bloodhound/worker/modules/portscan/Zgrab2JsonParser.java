package org.freedonia.bloodhound.worker.modules.portscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Optional;

/**
 * Pure parse of zgrab2's per-target JSON output - no process invocation,
 * fully unit-testable against canned output. Schemas below confirmed against
 * a real zgrab2 v1.0.0 build, not guessed from documentation:
 *
 * <pre>
 * banner: {"ip":"1.2.3.4","data":{"banner":{"status":"success","result":{"banner":"SSH-2.0-..."}}}}
 * http:   {"ip":"1.2.3.4","data":{"http":{"status":"success","result":{"response":{"headers":{"server":["Apache/2.4.7"]}}}}}}
 * </pre>
 *
 * On any non-"success" status (connection-timeout, connection-refused, ...)
 * there's no {@code result} node - both methods return empty in that case,
 * same as "nothing identified" rather than an error, since an unidentified
 * port is still a legitimately open one.
 */
public final class Zgrab2JsonParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Zgrab2JsonParser() {}

    public static Optional<String> parseBannerText(String json) {
        JsonNode result = successResult(json, "banner");
        if (result == null) {
            return Optional.empty();
        }
        return textAt(result, "banner");
    }

    public static Optional<String> parseHttpServerHeader(String json) {
        JsonNode result = successResult(json, "http");
        if (result == null) {
            return Optional.empty();
        }
        JsonNode server = result.path("response").path("headers").path("server");
        if (server.isArray() && server.size() > 0) {
            return Optional.ofNullable(blankToNull(server.get(0).asText(null)));
        }
        return Optional.empty();
    }

    private static JsonNode successResult(String json, String moduleName) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode module = root.path("data").path(moduleName);
            if (!"success".equals(module.path("status").asText(null))) {
                return null;
            }
            JsonNode result = module.path("result");
            return result.isMissingNode() ? null : result;
        } catch (Exception e) {
            return null;
        }
    }

    private static Optional<String> textAt(JsonNode node, String field) {
        return Optional.ofNullable(blankToNull(node.path(field).asText(null)));
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
