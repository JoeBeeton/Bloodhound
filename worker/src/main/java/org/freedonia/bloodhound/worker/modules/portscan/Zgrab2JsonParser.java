package org.freedonia.bloodhound.worker.modules.portscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Pure parse of zgrab2's per-target JSON output - no process invocation,
 * fully unit-testable against canned output. Schemas below confirmed against
 * a real zgrab2 v1.0.0 build, not guessed from documentation:
 *
 * <pre>
 * banner: {"ip":"1.2.3.4","data":{"banner":{"status":"success","result":{"banner":"SSH-2.0-..."}}}}
 * http:   {"ip":"1.2.3.4","data":{"http":{"status":"success","result":{"response":{"headers":{"server":["Apache/2.4.7"]}}}}}}
 * ssh:    {"ip":"1.2.3.4","data":{"ssh":{"status":"success","result":{"server_key_exchange":{
 *             "kex_algorithms":[...],"host_key_algorithms":[...],
 *             "client_to_server_ciphers":[...],"server_to_client_ciphers":[...],
 *             "client_to_server_macs":[...],"server_to_client_macs":[...]}}}}} (captured live
 *             against github.com:22)
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

    /** The server's own offered algorithm lists - both directions' ciphers/MACs unioned (client-to-server and server-to-client are near-always identical in practice, but union rather than assume). */
    public record SshAlgorithms(
            List<String> kexAlgorithms, List<String> hostKeyAlgorithms, List<String> ciphers, List<String> macs) {}

    public static Optional<SshAlgorithms> parseSshAlgorithms(String json) {
        JsonNode result = successResult(json, "ssh");
        if (result == null) {
            return Optional.empty();
        }
        JsonNode kex = result.path("server_key_exchange");
        if (kex.isMissingNode()) {
            return Optional.empty();
        }
        Set<String> ciphers = new LinkedHashSet<>();
        ciphers.addAll(toStringList(kex.path("client_to_server_ciphers")));
        ciphers.addAll(toStringList(kex.path("server_to_client_ciphers")));
        Set<String> macs = new LinkedHashSet<>();
        macs.addAll(toStringList(kex.path("client_to_server_macs")));
        macs.addAll(toStringList(kex.path("server_to_client_macs")));
        return Optional.of(new SshAlgorithms(
                toStringList(kex.path("kex_algorithms")), toStringList(kex.path("host_key_algorithms")),
                new ArrayList<>(ciphers), new ArrayList<>(macs)));
    }

    private static List<String> toStringList(JsonNode arrayNode) {
        List<String> result = new ArrayList<>();
        if (arrayNode.isArray()) {
            for (JsonNode n : arrayNode) {
                if (n.isTextual()) {
                    result.add(n.asText());
                }
            }
        }
        return result;
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
