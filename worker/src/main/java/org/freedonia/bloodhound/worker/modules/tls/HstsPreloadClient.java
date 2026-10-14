package org.freedonia.bloodhound.worker.modules.tls;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.freedonia.bloodhound.common.net.ScanUserAgent;

/**
 * hstspreload.org's own public status API - a free, no-key JSON endpoint that answers whether a
 * domain is actually on the list browsers ship, as opposed to merely sending a header that claims
 * the preload token (see TlsDecisionLogic#hstsFindings). Not target-controlled - this is a fixed,
 * trusted third-party domain queried with the scanned hostname as a query parameter only, so none
 * of the SSRF/redirect concerns SafeHttpGet exists for apply here (there's no target-influenceable
 * redirect to protect against).
 *
 * <p>Verified live against the real API before writing the parser: {@code
 * https://hstspreload.org/api/v2/status?domain=github.com} returns {@code {"name":"github.com",
 * "status":"preloaded","bulk":true,"preloadedDomain":"github.com"}}; a domain that's never
 * submitted returns {@code {"name":"example.com","status":"unknown","bulk":false,
 * "preloadedDomain":""}}.
 */
class HstsPreloadClient {

    private static final String BASE_URL = "https://hstspreload.org/api/v2/status?domain=";
    private static final Duration TIMEOUT = Duration.ofSeconds(8);

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper mapper = new ObjectMapper();

    String fetchRaw(String hostname) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + hostname))
                .timeout(TIMEOUT)
                .header("User-Agent", ScanUserAgent.VALUE)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("hstspreload.org returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    /** Pure - no network calls. Returns null (not "unknown") on any parse failure, same as a fetch failure. */
    String parseStatus(String json) {
        if (json == null) {
            return null;
        }
        try {
            JsonNode root = mapper.readTree(json);
            JsonNode status = root.get("status");
            return status == null || status.isNull() ? null : status.asText();
        } catch (Exception e) {
            return null;
        }
    }
}
