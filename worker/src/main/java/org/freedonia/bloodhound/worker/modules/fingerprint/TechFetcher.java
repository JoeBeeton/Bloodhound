package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Fetch side of tech-stack fingerprinting: a single plain GET, same shape as
 * HttpHeaderFetcher, except the body is kept (needed for meta-generator tags
 * and script/link signatures) rather than discarded. Bounded by request
 * timeout only, not a byte cap - real pages this targets a passive scanner
 * against are not adversarially huge, and every other module in this project
 * uses the same timeout-based bounding rather than a custom size-limited body
 * subscriber. Redirects are followed manually via SafeHttpGet (SSRF guard:
 * see HttpHeaderFetcher's javadoc for why Redirect.NORMAL is not safe here) -
 * specifically {@link SafeHttpGet#getWithRedirectChainHeaders}, not the
 * plain {@code get}, since a redirect hop's own headers can themselves be a
 * real fingerprinting signal (confirmed live: WordPress's canonical-URL
 * redirect sets {@code X-Redirect-By: WordPress} on the 301 itself, never
 * repeated anywhere in the final page).
 */
public class TechFetcher {

    private static final int BODY_CHAR_CAP = 300_000;
    private static final int MAX_REDIRECTS = 5;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public TechFetchResult fetch(String hostname) throws ScanModuleException {
        try {
            return toResult(get("https://" + hostname + "/"));
        } catch (Exception httpsFailure) {
            try {
                return toResult(get("http://" + hostname + "/"));
            } catch (Exception httpFailure) {
                throw new ScanModuleException("failed to reach " + hostname + " over HTTPS or HTTP", httpFailure);
            }
        }
    }

    /**
     * A second, targeted GET for WordPress's REST API discovery document
     * ({@code /wp-json/}) - only ever called by FingerprintModule once
     * WordPress has already been positively identified from the homepage
     * fetch above, so this doesn't add a second request to every single
     * scanned host, just the ones actually worth it. Returns null on any
     * failure (unreachable, non-200, whatever) rather than throwing - this
     * is a best-effort enrichment on top of an already-successful
     * fingerprint, not something that should fail the whole host.
     *
     * <p>Confirmed live to work even on WordPress installs that otherwise
     * strip every other fingerprinting signal (no generator tag, no
     * wp-content/wp-includes references anywhere in the page): {@code
     * /wp-json/} is enabled by default and left reachable far more often
     * than not, since disabling it breaks the block editor and most modern
     * plugins that depend on it - a much bigger deal for a site owner to
     * break than removing a meta tag.
     */
    public String fetchWpJson(String hostname) {
        try {
            return get("https://" + hostname + "/wp-json/").response().body();
        } catch (Exception httpsFailure) {
            try {
                return get("http://" + hostname + "/wp-json/").response().body();
            } catch (Exception httpFailure) {
                return null;
            }
        }
    }

    private SafeHttpGet.RedirectChainResult<String> get(String url) throws IOException, InterruptedException {
        return SafeHttpGet.getWithRedirectChainHeaders(
                client,
                url,
                Duration.ofSeconds(8),
                "Bloodhound-ASM/1.0 (+passive surface scan)",
                HttpResponse.BodyHandlers.ofString(),
                MAX_REDIRECTS);
    }

    private TechFetchResult toResult(SafeHttpGet.RedirectChainResult<String> result) {
        HttpResponse<String> response = result.response();
        String body = response.body();
        if (body != null && body.length() > BODY_CHAR_CAP) {
            body = body.substring(0, BODY_CHAR_CAP);
        }
        return new TechFetchResult(result.allHopHeaders(), response.headers().allValues("set-cookie"), body == null ? "" : body);
    }
}
