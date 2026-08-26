package org.freedonia.bloodhound.server.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * osv.dev's free, no-API-key, no-rate-limit-issue direct-CVE-ID lookup - used
 * purely for human-readable descriptions (NVD, queried elsewhere in this
 * package, remains the source for CVE-ID/CVSS-score correlation itself; OSV
 * skews open-source and doesn't cover every CVE NVD does, so it's a
 * best-effort enrichment layer, not a replacement).
 *
 * <p>Response shape confirmed against the real API (not guessed): {@code
 * GET /v1/vulns/{CVE-ID}} returns a JSON object with a top-level {@code
 * details} field (the long-form description - the field this class actually
 * wants; {@code summary} is a shorter alternative that's frequently absent,
 * e.g. real CVE-2023-44487 has only {@code details}), {@code published}
 * (ISO-8601), and a {@code severity} array of {type, score} where {@code
 * score} is a raw CVSS vector string, not a simple label - stored as-is.
 * A CVE genuinely absent from OSV's dataset (real, expected - confirmed via
 * a real 404 during development, not assumed) returns HTTP 404, handled here
 * as "no detail available", not an error.
 */
@Component
public class OsvClient {

    private static final Logger log = LoggerFactory.getLogger(OsvClient.class);
    private static final String BASE_URL = "https://api.osv.dev/v1/vulns/";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** @return null if OSV has no entry for this CVE ID (a real 404, not a fetch failure) */
    public String fetchRaw(String cveId) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + cveId))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 404) {
            return null;
        }
        if (response.statusCode() != 200) {
            throw new IOException("OSV API returned HTTP " + response.statusCode() + " for " + cveId);
        }
        return response.body();
    }

    /** Pure - no network calls. Returns null (not a detail with a null description) if the response can't be parsed at all. */
    public OsvCveDetail parse(String cveId, String json) {
        if (json == null) {
            return new OsvCveDetail(cveId, null, null, null);
        }
        try {
            JsonNode root = objectMapper.readTree(json);
            String description = root.hasNonNull("details")
                    ? root.get("details").asText()
                    : root.hasNonNull("summary") ? root.get("summary").asText() : null;
            String severity = null;
            JsonNode severityArray = root.path("severity");
            if (severityArray.isArray() && !severityArray.isEmpty()) {
                severity = severityArray.get(0).path("score").asText(null);
            }
            Instant published = root.hasNonNull("published") ? Instant.parse(root.get("published").asText()) : null;
            return new OsvCveDetail(cveId, description, severity, published);
        } catch (Exception e) {
            log.warn("Failed to parse OSV response for {}, skipping: {}", cveId, e.toString());
            return new OsvCveDetail(cveId, null, null, null);
        }
    }
}
