package org.freedonia.bloodhound.server.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * NVD's free, no-API-key CVE search, using {@code virtualMatchString} rather
 * than the more obvious-looking {@code cpeName} (exact-URI lookup).
 *
 * <p>This was a real, empirically-discovered correctness pitfall while
 * building this class: {@code cpeName} requires knowing NVD's exact
 * catalogued CPE vendor *and* the literal version string it enumerated -
 * querying {@code cpe:2.3:a:nginx:nginx:1.20.0:...} (a reasonable-looking
 * guess) returns zero results, both because nginx's real NVD vendor is
 * "f5", not "nginx" (confirmed by inspecting real API responses), and
 * because many CVEs are defined via version *ranges*
 * (versionStartIncluding/versionEndExcluding) rather than an exact
 * per-version CPE entry, which {@code cpeName} can't match at all.
 * {@code virtualMatchString=cpe:2.3:a:*:{product}:{version}} - wildcard
 * vendor, our specific version - sidesteps both problems: NVD's own
 * matching engine evaluates the version (whether by range or exact
 * enumeration) against every configuration node server-side, so this class
 * never needs to reimplement CPE version-range comparison itself. Verified
 * directly against the real API: a known-old vulnerable nginx version
 * correctly returns CVE-2009-3896 (which explicitly does NOT apply to a
 * modern 1.20.0 query), while 1.20.0 instead returns real, different,
 * modern nginx CVEs (e.g. CVE-2021-23017, CVE-2023-44487) - confirming the
 * version filtering is genuinely happening, not just returning everything.
 */
@Component
public class NvdClient {

    private static final Logger log = LoggerFactory.getLogger(NvdClient.class);
    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** @param productSlug NVD's CPE "product" component (not our own technology display name - see ProductSlugMapper), e.g. "nginx", "http_server", "php", "wordpress". */
    public String fetchRaw(String productSlug, String version) throws IOException, InterruptedException {
        String matchString = "cpe:2.3:a:*:" + productSlug + ":" + version;
        String url = BASE_URL + "?virtualMatchString=" + URLEncoder.encode(matchString, StandardCharsets.UTF_8)
                + "&resultsPerPage=20";
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 404) {
            // NVD returns 404 (not an empty result set) for a virtualMatchString whose
            // product component doesn't exist in its CPE dictionary at all - a real,
            // expected outcome for a technology name we don't have good CPE mapping
            // for, not a fetch failure.
            return null;
        }
        if (response.statusCode() != 200) {
            throw new IOException("NVD API returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    /** Pure - no network calls. Prefers CVSS v3.1, then v3.0, then v2 (oldest CVEs often only have v2 data at all). */
    public List<NvdCveResult> parse(String json) {
        if (json == null) {
            return List.of();
        }
        List<NvdCveResult> results = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            for (JsonNode item : root.path("vulnerabilities")) {
                JsonNode cve = item.path("cve");
                String id = cve.path("id").asText(null);
                if (id == null) {
                    continue;
                }
                JsonNode metrics = cve.path("metrics");
                JsonNode best = firstPresent(metrics, "cvssMetricV31", "cvssMetricV30", "cvssMetricV2");
                if (best == null || !best.isArray() || best.isEmpty()) {
                    results.add(new NvdCveResult(id, null, null));
                    continue;
                }
                JsonNode cvssData = best.get(0).path("cvssData");
                Double score = cvssData.has("baseScore") ? cvssData.get("baseScore").asDouble() : null;
                // CVSS v2 has no baseSeverity inside cvssData itself - it sits one level
                // up, alongside cvssData, unlike v3.x where it's a cvssData field.
                String severity = cvssData.has("baseSeverity")
                        ? cvssData.get("baseSeverity").asText()
                        : best.get(0).path("baseSeverity").asText(null);
                results.add(new NvdCveResult(id, severity, score));
            }
        } catch (Exception e) {
            log.warn("Failed to parse NVD response, skipping this batch: {}", e.toString());
            return List.of();
        }
        return results;
    }

    private static JsonNode firstPresent(JsonNode metrics, String... keys) {
        for (String key : keys) {
            if (metrics.has(key)) {
                return metrics.get(key);
            }
        }
        return null;
    }
}
