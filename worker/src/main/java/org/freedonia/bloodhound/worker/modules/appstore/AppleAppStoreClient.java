package org.freedonia.bloodhound.worker.modules.appstore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.springframework.stereotype.Component;

/**
 * Apple's iTunes Search API - free, no API key, no auth, officially documented
 * (developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/).
 * Verified live before building this: {@code https://itunes.apple.com/search?term=example+finance&
 * entity=software&limit=5} returns real, current results including one genuinely suspicious case
 * - an app titled "EXAMPLE Finance Tracker" published by an unrelated individual developer, not
 * "Example Finance Ltd" (the real company's own apps all correctly show that seller name).
 *
 * <p>{@code country=gb}: Bloodhound's real tracked targets are UK companies, so the GB storefront
 * is the relevant one to search - a scoped choice (not configurable per-target, since Target has
 * no stored market/country field), same kind of documented simplification as
 * PermutationGenerator's own last-dot-only TLD split.
 */
@Component
public class AppleAppStoreClient {

    private static final String BASE_URL = "https://itunes.apple.com/search";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final int RESULT_LIMIT = 25;

    private final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String fetchRaw(String searchTerm) throws Exception {
        String encoded = URLEncoder.encode(searchTerm, StandardCharsets.UTF_8);
        URI uri = URI.create(BASE_URL + "?term=" + encoded + "&entity=software&country=gb&limit=" + RESULT_LIMIT);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(TIMEOUT)
                .header("User-Agent", ScanUserAgent.VALUE)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("iTunes Search API returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    /** Pure - no network calls. A malformed/unexpected response yields an empty list rather than throwing, same best-effort posture as every other external-feed parser in this codebase. */
    public List<AppResult> parse(String json) {
        List<AppResult> results = new ArrayList<>();
        if (json == null) {
            return results;
        }
        try {
            JsonNode root = objectMapper.readTree(json);
            for (JsonNode r : root.path("results")) {
                String appId = textOrNull(r, "trackId");
                results.add(new AppResult(
                        "APPLE_APP_STORE",
                        appId,
                        textOrNull(r, "trackName"),
                        textOrNull(r, "sellerName"),
                        textOrNull(r, "trackViewUrl"),
                        r.has("averageUserRating") ? r.path("averageUserRating").asDouble() : null,
                        r.has("userRatingCount") ? r.path("userRatingCount").asInt() : null));
            }
        } catch (Exception ignored) {
            return List.of();
        }
        return results;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }
}
