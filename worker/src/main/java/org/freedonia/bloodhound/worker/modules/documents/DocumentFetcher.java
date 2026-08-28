package org.freedonia.bloodhound.worker.modules.documents;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.OptionalLong;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.worker.ratelimit.HostnameRateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fetch side of document-metadata discovery: one plain GET for the homepage
 * (to find document links - see {@link DocumentLinkDecisionLogic}), then one
 * bounded GET per discovered document. Genuinely passive - both are requests
 * any browser visiting the page would make.
 */
public class DocumentFetcher {

    private static final Logger log = LoggerFactory.getLogger(DocumentFetcher.class);

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final int MAX_REDIRECTS = 5;
    private static final String USER_AGENT = ScanUserAgent.VALUE;

    /** A legitimate handbook/whitepaper-sized PDF is often several MB; this bounds worst-case memory/time without rejecting realistic documents. */
    static final long MAX_DOCUMENT_BYTES = 20L * 1024 * 1024;

    /** Homepage HTML only needs enough to find document links near the top of the page - nowhere near MAX_DOCUMENT_BYTES. */
    private static final int HOMEPAGE_BODY_CHAR_CAP = 300_000;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public String fetchHomepage(String hostname) throws ScanModuleException {
        HostnameRateLimiter.shared().acquire(hostname);
        try {
            return getString("https://" + hostname + "/");
        } catch (Exception httpsFailure) {
            try {
                return getString("http://" + hostname + "/");
            } catch (Exception httpFailure) {
                throw new ScanModuleException("failed to reach " + hostname + " over HTTPS or HTTP", httpFailure);
            }
        }
    }

    /**
     * Returns null (never throws) on any failure - a document 404ing,
     * timing out, or exceeding {@link #MAX_DOCUMENT_BYTES} just means one
     * fewer document gets checked, not a failed scan; the same
     * best-effort-enrichment contract as {@code TechFetcher#fetchWpJson}.
     */
    public byte[] fetchDocument(String documentUrl) {
        HostnameRateLimiter.shared().acquire(java.net.URI.create(documentUrl).getHost());
        try {
            SafeHttpGet.RedirectChainResult<InputStream> result = SafeHttpGet.getWithRedirectChainHeaders(
                    client, documentUrl, REQUEST_TIMEOUT, USER_AGENT, HttpResponse.BodyHandlers.ofInputStream(), MAX_REDIRECTS);
            HttpResponse<InputStream> response = result.response();
            if (response.statusCode() != 200) {
                return null;
            }
            OptionalLong declaredLength = response.headers().firstValueAsLong("content-length");
            if (declaredLength.isPresent() && declaredLength.getAsLong() > MAX_DOCUMENT_BYTES) {
                return null;
            }
            try (InputStream is = response.body()) {
                byte[] buf = is.readNBytes((int) MAX_DOCUMENT_BYTES + 1);
                if (buf.length > MAX_DOCUMENT_BYTES) {
                    return null; // exceeded the cap even without a (trustworthy) declared Content-Length
                }
                return buf;
            }
        } catch (Exception e) {
            log.debug("document fetch of {} failed: {}", documentUrl, e.getMessage());
            return null;
        }
    }

    // ofInputStream()+readCappedUtf8, not ofString(): a security review found ofString()
    // buffers the ENTIRE response into memory with no size limit - a scanned target
    // (attacker-influenceable by definition) could stream gigabytes within the request timeout
    // and exhaust the shared worker JVM's heap. fetchDocument above already avoids this for
    // binary downloads via readNBytes; this closes the same gap for the homepage HTML fetch.
    private String getString(String url) throws Exception {
        InputStream body =
                SafeHttpGet.get(client, url, REQUEST_TIMEOUT, USER_AGENT, HttpResponse.BodyHandlers.ofInputStream(), MAX_REDIRECTS)
                        .body();
        return SafeHttpGet.readCappedUtf8(body, HOMEPAGE_BODY_CHAR_CAP);
    }
}
