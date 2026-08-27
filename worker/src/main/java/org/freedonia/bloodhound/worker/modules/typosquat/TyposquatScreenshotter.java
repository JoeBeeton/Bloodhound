package org.freedonia.bloodhound.worker.modules.typosquat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Calls the browserless/chromium sidecar (see docker-compose.yml) to render
 * a hostname's homepage and capture a small PNG screenshot, for
 * {@link PerceptualHash}-based visual-similarity comparison against the
 * real target.
 *
 * <p>The sidecar has full network access within the Docker network (it's a
 * real browser, not a scoped HTTP client) - unlike this codebase's other
 * fetchers, which make the outbound connection themselves and can reuse
 * {@link SafeAddressValidator}/{@code SafeHttpGet} directly, a URL handed to
 * the sidecar is resolved and fetched entirely on its side. Validating the
 * hostname here before ever sending it - same requirement, same check,
 * different reason: without it, the sidecar could be pointed at an internal
 * service by hostname (e.g. central-server's actuator endpoints) rather
 * than an external target.
 *
 * <p>Best-effort like every other non-essential signal in this module
 * (WHOIS lookups, registration dates): a screenshot failure - target down,
 * sidecar error, timeout - never fails the typosquat check itself, it just
 * means no visual-similarity score for that candidate.
 */
public class TyposquatScreenshotter {

    private static final Logger log = LoggerFactory.getLogger(TyposquatScreenshotter.class);

    /** Small on purpose: this is a similarity signal + UI thumbnail, not a full-resolution archive. */
    private static final int VIEWPORT_WIDTH = 800;
    private static final int VIEWPORT_HEIGHT = 600;
    private static final Duration PAGE_LOAD_TIMEOUT = Duration.ofSeconds(8);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    // HTTP/1.1 explicitly - confirmed live that the sidecar's JSON body parser rejects a
    // perfectly valid JSON body ("Couldn't parse JSON body") when JDK HttpClient's default
    // HTTP/2-upgrade-attempt behavior is left in place against this particular Node.js/Express
    // server, a known class of interop issue between JDK HttpClient and servers that don't
    // fully support the h2c upgrade path cleanly.
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    private final String baseUrl;
    private final String apiKey;

    public TyposquatScreenshotter(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
    }

    /** Returns null on any failure (unsafe host, unreachable sidecar, page load timeout, non-200 response) - never throws. */
    public byte[] capture(String hostname) {
        try {
            SafeAddressValidator.requireSafeIfResolvable(hostname);
        } catch (Exception e) {
            log.debug("refusing to screenshot {} - resolves to an unsafe address", hostname);
            return null;
        }
        try {
            return doCapture("https://" + hostname + "/");
        } catch (Exception httpsFailure) {
            try {
                return doCapture("http://" + hostname + "/");
            } catch (Exception httpFailure) {
                log.debug(
                        "screenshot capture failed for {} (https: {}, http: {})",
                        hostname,
                        httpsFailure.toString(),
                        httpFailure.toString());
                return null;
            }
        }
    }

    private byte[] doCapture(String pageUrl) throws Exception {
        String requestBody =
                """
                {"url":"%s","options":{"type":"png"},"viewport":{"width":%d,"height":%d},"gotoOptions":{"timeout":%d}}
                """
                        .formatted(
                                escapeJson(pageUrl),
                                VIEWPORT_WIDTH,
                                VIEWPORT_HEIGHT,
                                PAGE_LOAD_TIMEOUT.toMillis())
                        .strip();

        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/screenshot?token=" + apiKey))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            log.debug(
                    "non-200 from screenshotter for {}: status={}",
                    pageUrl,
                    response.statusCode());
            return null;
        }
        return response.body();
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
