package org.freedonia.bloodhound.server.jobqueue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Reads the single-host {@code {"host": "..."}} key a Tier 2 (one-job-per-host) job's
 * payload carries - see ScanRunService#createDeepScan and the worker's
 * PayloadSubdomains#singleHost. Null for anything else (Tier 1's multi-host
 * {@code {"subdomains": [...]}} payload, CT_CHECK's empty {@code {}}, or a malformed
 * payload) - there's no single "the host" to report for those, which is a normal,
 * expected outcome here, not an error.
 */
final class JobPayloadHost {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JobPayloadHost() {}

    static String extract(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(payloadJson).get("host");
            return node != null && node.isTextual() ? node.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
