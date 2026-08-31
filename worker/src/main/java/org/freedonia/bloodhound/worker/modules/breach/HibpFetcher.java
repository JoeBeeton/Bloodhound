package org.freedonia.bloodhound.worker.modules.breach;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;

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
    /** Was its own drifted string ("passive breach correlation") - unified to the shared
     * ScanUserAgent so every outbound request identifies as Bloodhound the same way. */
    private static final String USER_AGENT = ScanUserAgent.VALUE;
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    /**
     * A security review found both calls below used BodyHandlers.ofString(), buffering the ENTIRE
     * response into memory before this class ever sees it - the same issue already fixed
     * elsewhere in the worker module (TechFetcher, DocumentFetcher, CrtShSource, WhoisFetcher) via
     * SafeHttpGet#readCappedUtf8. Lower risk here than those - haveibeenpwned.com is a fixed,
     * trusted third-party security API, not attacker/scanned-target-influenced content - but the
     * fix is the same one-line swap and there's no reason to leave this one call site
     * inconsistent with every other outbound HTTP fetch in the module. HIBP's actual responses are
     * small JSON (a list of breach names, or one breach's metadata), nowhere near this cap.
     */
    private static final int MAX_RESPONSE_BYTES = 200_000;

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
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        return new RawResponse(response.statusCode(), SafeHttpGet.readCappedUtf8(response.body(), MAX_RESPONSE_BYTES));
    }

    /** Unauthenticated - no hibp-api-key header, per HIBP's own docs for this specific endpoint. */
    RawResponse fetchBreachDetail(String breachName) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/breach/" + encode(breachName)))
                .timeout(TIMEOUT)
                .header("User-Agent", USER_AGENT)
                .GET()
                .build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        return new RawResponse(response.statusCode(), SafeHttpGet.readCappedUtf8(response.body(), MAX_RESPONSE_BYTES));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
