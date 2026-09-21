package org.freedonia.bloodhound.server.eol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * endoflife.date's free, no-API-key product API - a static JSON file served from a CDN
 * (confirmed live while scoping this feature: {@code cache-control: public,max-age=0,
 * must-revalidate}, a CDN edge-cache hit, no {@code X-RateLimit-*} headers at all) rather
 * than a rate-limited service like NVD, so unlike {@code vuln.NvdClient} there's no
 * inter-call spacing concern here.
 *
 * <p>One call per <b>product</b> (not per version) returns every release cycle at once -
 * see {@link EolRelease}. Fetch and parse are split the same way every other external
 * data source in this codebase splits network I/O from pure interpretation, so parse()
 * is unit-testable against a canned fixture with zero network calls.
 */
@Component
public class EndOfLifeClient {

    private static final Logger log = LoggerFactory.getLogger(EndOfLifeClient.class);
    private static final String BASE_URL = "https://endoflife.date/api/v1/products/";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** @return null if this slug doesn't exist in endoflife.date's catalog (a real 404, not a fetch failure - e.g. a slug typo or a product removed from their catalog since EolProductSlugMapper was last checked). */
    public String fetchRaw(String slug) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + slug))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 404) {
            return null;
        }
        if (response.statusCode() != 200) {
            throw new IOException("endoflife.date API returned HTTP " + response.statusCode() + " for " + slug);
        }
        return response.body();
    }

    /** Pure - no network calls. Malformed individual release entries are skipped rather than failing the whole parse. */
    public List<EolRelease> parse(String json) {
        if (json == null) {
            return List.of();
        }
        List<EolRelease> releases = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            for (JsonNode r : root.path("result").path("releases")) {
                String cycle = textOrNull(r, "name");
                if (cycle == null) {
                    continue;
                }
                releases.add(new EolRelease(
                        cycle,
                        r.path("isEol").asBoolean(false),
                        dateOrNull(r, "eolFrom"),
                        r.path("isMaintained").asBoolean(false),
                        textOrNull(r.path("latest"), "name")));
            }
        } catch (Exception e) {
            log.warn("Failed to parse endoflife.date response, skipping this product this cycle: {}", e.toString());
            return List.of();
        }
        return releases;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static LocalDate dateOrNull(JsonNode node, String field) {
        String text = textOrNull(node, field);
        if (text == null) {
            return null;
        }
        try {
            return LocalDate.parse(text);
        } catch (Exception e) {
            return null;
        }
    }
}
