package org.freedonia.bloodhound.worker.modules.zap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fetch side of the ZAP active-scan module: drives ZAP's REST API through a
 * spider -&gt; active-scan -&gt; alerts-retrieval workflow. This is the one
 * class in this module that touches the network, so - consistent with every
 * other fetch class in this codebase (NaabuFetcher, TlsFetcher, ...) - it
 * isn't unit-tested directly; {@link ZapAlertParser}/{@link ZapAlertMapper}
 * carry the real test coverage.
 *
 * <p>Bounded like every other worker module: the spider is capped
 * (maxChildren) so it can't turn into an unbounded crawl even against a
 * larger real app later, and the whole spider+ascan workflow has a single
 * hard wall-clock budget. On timeout at either phase, this returns whatever
 * alerts ZAP has found <i>so far</i> rather than throwing away partial
 * results - same "report what you found" philosophy as subdomain enum's
 * per-source cap and every other subprocess wrapper's hard process timeout.
 *
 * <p>SSRF guard: unlike every other outbound-fetch class in this codebase
 * (SafeHttpGet, NucleiFetcher, TlsFetcher, ExposedPathFetcher), the actual
 * TCP connect here happens inside the separate {@code zap} container, not in
 * this process - same "hands a hostname to a sidecar" shape as
 * TyposquatScreenshotter, and the same reason this needs its own check:
 * without it, ZAP could be pointed at internal infrastructure by hostname
 * (e.g. central-server's actuator endpoints, or postgres) and would happily
 * fire genuine SQLi/XSS/path-traversal payloads at it - categorically worse
 * than a passive fetch landing somewhere internal. {@link
 * SafeAddressValidator#requireSafeIfResolvable} is checked twice, not once:
 * immediately (closing the base case) and again right before the active-scan
 * phase specifically, since spidering alone can run for minutes and ascan is
 * where the real attack payloads actually fire - re-checking narrows the
 * DNS-rebinding window around the genuinely dangerous phase, though (like
 * every other re-resolve-based check in this codebase) it can't close a
 * rebind racing the individual request itself, a documented residual gap.
 */
public class ZapScanRunner {

    private static final Logger log = LoggerFactory.getLogger(ZapScanRunner.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Duration TOTAL_BUDGET = Duration.ofMinutes(12);
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(5);
    private static final int SPIDER_MAX_CHILDREN = 10;

    /**
     * A security review found callRaw used BodyHandlers.ofString(), buffering the entire response
     * into memory with no size limit - the same issue already fixed elsewhere in the worker
     * module via SafeHttpGet. Lower risk than most of those fixes - ZAP's own control API is a
     * trusted internal Docker sidecar, not directly attacker-controlled - but its alert-list
     * response size is driven by how much attack surface the actual scanned target has, so a
     * large or pathological target could still produce a large response through it. Generous:
     * ZAP's alerts endpoint returns one JSON object per finding across a whole spider+ascan run,
     * legitimately larger than a single API call's typical payload elsewhere in this codebase.
     */
    private static final int MAX_RESPONSE_BYTES = 10_000_000;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final String baseUrl;
    private final String apiKey;

    public ZapScanRunner(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
    }

    /** Runs the full spider+ascan workflow against {@code hostname} and returns the raw /JSON/core/view/alerts/ response body. */
    public String runFullScan(String hostname) throws ScanModuleException {
        requireSafeHost(hostname);
        Instant deadline = Instant.now().plus(TOTAL_BUDGET);
        disableNoiseScanners();

        // HTTPS first, HTTP fallback - the same order every other HTTP-fetching module in this
        // codebase already uses (see HttpHeaderFetcher), not followed here previously: this
        // used to hardcode plain http://, so any HTTPS-only host (the norm today, especially
        // anything behind a CDN) could never be scanned at all - it would spider zero pages and
        // then fail on ascan with an opaque "HTTP 400" that gave no hint why. Confirmed for real
        // against a live target during investigation of that exact symptom.
        SpiderResult spidered = spiderAndCheck("https://" + hostname + "/", deadline);
        if (!spidered.reachable()) {
            spidered = spiderAndCheck("http://" + hostname + "/", deadline);
        }
        if (!spidered.reachable()) {
            throw new ScanModuleException(
                    "ZAP spider found nothing to scan for " + hostname
                            + " over HTTPS or HTTP - the host may be unreachable or not serving web traffic");
        }
        String targetUrl = spidered.targetUrl();

        // Re-checked here, not just once at entry: spidering alone can run for minutes, and this
        // is the point where ZAP starts firing genuine attack payloads - the highest-value place
        // to narrow the DNS-rebinding window, even though it can't close it entirely.
        requireSafeHost(hostname);
        String ascanId = call("/JSON/ascan/action/scan/", Map.of("url", targetUrl, "recurse", "true"))
                .path("scan").asText();
        boolean ascanFinished = pollUntilComplete("active scan", () -> ascanStatusPercent(ascanId), deadline);
        if (!ascanFinished) {
            log.warn("ZAP active scan against {} did not finish within budget - retrieving whatever alerts have been raised so far", hostname);
        }

        return callRaw("/JSON/core/view/alerts/", Map.of("baseurl", targetUrl));
    }

    /**
     * Before the spider, not just before ascan: passive rules evaluate every response ZAP sees,
     * spidered ones included. Best-effort - ZapAlertMapper drops these ids anyway, so a failed
     * call here costs wasted ZAP time, not wrong findings, and isn't worth failing the scan over.
     * Idempotent, so it's simply repeated per run rather than tracked per ZAP instance.
     */
    private void disableNoiseScanners() {
        try {
            call("/JSON/pscan/action/disableScanners/", Map.of("ids", String.join(",", ZapNoiseRules.PASSIVE_SCANNER_IDS)));
            call("/JSON/ascan/action/disableScanners/", Map.of("ids", String.join(",", ZapNoiseRules.ACTIVE_SCANNER_IDS)));
        } catch (ScanModuleException e) {
            log.warn("could not disable ZAP noise scanners - their alerts will be dropped at mapping instead: {}", e.getMessage());
        }
    }

    private record SpiderResult(String targetUrl, boolean reachable) {}

    /**
     * Runs the spider against one scheme and reports whether the target was actually reachable
     * - the signal used to decide whether this scheme is worth handing to ascan, or whether to
     * fall back to the other one.
     *
     * <p><b>Deliberately not based on {@code /JSON/spider/view/results/}</b>, despite that
     * looking like the obvious choice - empirically verified (against both a genuinely
     * unreachable host and a real, fully-crawled one, via direct ZAP API calls) to be
     * unreliable in both directions: it lists attempted-but-never-actually-fetched URLs for an
     * unreachable host (so it reads "non-empty" even when nothing was ever reached), and comes
     * back completely empty for a real host ZAP successfully exchanged 4600+ real HTTP messages
     * with (apparently a live in-flight view that clears once the spider fully settles, not a
     * durable record of what succeeded). The combination that actually discriminates correctly,
     * confirmed the same way: {@code numberOfMessages} (real HTTP round-trips ZAP completed for
     * this base URL) is non-zero, AND {@code /JSON/spider/view/fullResults/}'s {@code
     * urlsIoError} bucket - which does durably persist connection-level failures - is empty. An
     * unreachable host produces the inverse: a handful of messages that are ALL in urlsIoError.
     */
    private SpiderResult spiderAndCheck(String targetUrl, Instant deadline) throws ScanModuleException {
        String spiderScanId = call("/JSON/spider/action/scan/",
                Map.of("url", targetUrl, "maxChildren", String.valueOf(SPIDER_MAX_CHILDREN), "recurse", "true"))
                .path("scan").asText();
        boolean spiderFinished = pollUntilComplete("spider", () -> spiderStatusPercent(spiderScanId), deadline);
        if (!spiderFinished) {
            log.warn("ZAP spider against {} did not finish within budget - proceeding on whatever was crawled so far", targetUrl);
        }

        long messageCount = call("/JSON/core/view/numberOfMessages/", Map.of("baseurl", targetUrl))
                .path("numberOfMessages").asLong(0);
        int ioErrorCount = call("/JSON/spider/view/fullResults/", Map.of("scanId", spiderScanId))
                .path("fullResults")
                .findValues("urlsIoError")
                .stream()
                .mapToInt(JsonNode::size)
                .sum();
        boolean reachable = messageCount > 0 && ioErrorCount == 0;
        return new SpiderResult(targetUrl, reachable);
    }

    private int spiderStatusPercent(String scanId) throws ScanModuleException {
        return call("/JSON/spider/view/status/", Map.of("scanId", scanId)).path("status").asInt(0);
    }

    private int ascanStatusPercent(String scanId) throws ScanModuleException {
        return call("/JSON/ascan/view/status/", Map.of("scanId", scanId)).path("status").asInt(0);
    }

    private interface PercentSupplier {
        int get() throws ScanModuleException;
    }

    private boolean pollUntilComplete(String phaseName, PercentSupplier percentSupplier, Instant deadline)
            throws ScanModuleException {
        while (Instant.now().isBefore(deadline)) {
            int percent = percentSupplier.get();
            if (percent >= 100) {
                return true;
            }
            try {
                Thread.sleep(POLL_INTERVAL.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ScanModuleException(phaseName + " polling was interrupted", e);
            }
        }
        return false;
    }

    private JsonNode call(String path, Map<String, String> params) throws ScanModuleException {
        String body = callRaw(path, params);
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            throw new ScanModuleException("failed to parse ZAP response from " + path + ": " + body, e);
        }
    }

    private String callRaw(String path, Map<String, String> params) throws ScanModuleException {
        StringBuilder query = new StringBuilder("apikey=").append(encode(apiKey));
        for (Map.Entry<String, String> entry : params.entrySet()) {
            query.append('&').append(entry.getKey()).append('=').append(encode(entry.getValue()));
        }
        URI uri = URI.create(baseUrl + path + "?" + query);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        try {
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                response.body().close();
                throw new ScanModuleException("ZAP API call to " + path + " returned HTTP " + response.statusCode());
            }
            return SafeHttpGet.readCappedUtf8(response.body(), MAX_RESPONSE_BYTES);
        } catch (java.io.IOException e) {
            throw new ScanModuleException("failed to reach ZAP at " + baseUrl + path, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanModuleException("ZAP API call to " + path + " was interrupted", e);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private static void requireSafeHost(String hostname) throws ScanModuleException {
        try {
            SafeAddressValidator.requireSafeIfResolvable(hostname);
        } catch (Exception e) {
            throw new ScanModuleException("refusing to actively scan " + hostname + ": " + e.getMessage(), e);
        }
    }
}
