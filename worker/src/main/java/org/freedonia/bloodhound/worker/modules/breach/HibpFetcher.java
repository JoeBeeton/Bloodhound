package org.freedonia.bloodhound.worker.modules.breach;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Fetch side of Have I Been Pwned's public API - no interpretation here (see
 * {@link HibpDecisionLogic}), just the two raw HTTP calls this module needs:
 * the authenticated domain-search lookup and the unauthenticated
 * per-breach detail lookup used to enrich each breach name it returns.
 *
 * <p>Every call carries a User-Agent - HIBP's API rejects requests without
 * one (documented behavior, not a guess), including the unauthenticated
 * {@code /breach/{name}} endpoint.
 */
class HibpFetcher {

    record RawResponse(int statusCode, String body) {}

    private static final String BASE_URL = "https://haveibeenpwned.com/api/v3";
    private static final String USER_AGENT = "Bloodhound-ASM/1.0 (+passive breach correlation)";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final String apiKey;

    HibpFetcher(String apiKey) {
        this.apiKey = apiKey;
    }

    RawResponse fetchDomainSearch(String domain) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/breacheddomain/" + encode(domain)))
                .timeout(TIMEOUT)
                .header("User-Agent", USER_AGENT)
                .header("hibp-api-key", apiKey)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return new RawResponse(response.statusCode(), response.body());
    }

    /** Unauthenticated - no hibp-api-key header, per HIBP's own docs for this specific endpoint. */
    RawResponse fetchBreachDetail(String breachName) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/breach/" + encode(breachName)))
                .timeout(TIMEOUT)
                .header("User-Agent", USER_AGENT)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return new RawResponse(response.statusCode(), response.body());
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
