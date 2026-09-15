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
        startFreshSession();
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

        return callRaw("/JSON/core/view/alerts/", Map.of("baseurl", targetUrl), ALERTS_FETCH_TIMEOUT);
    }

    /**
     * A live incident traced ZAP's own API becoming unresponsive (a 25s+ hang on even trivial
     * calls like numberOfMessages) back to its embedded HSQLDB-backed message-History table: a
     * thread dump under `jstack` during the hang showed 486 of 567 threads all blocked on the
     * same {@code ParosTableHistory} object monitor, and the one thread actually holding it was
     * deep inside HSQLDB's disk row cache (RandomAccessFile I/O evicting/paging cache blocks to
     * insert one history row) - a known HSQLDB characteristic where a CACHED table's per-insert
     * cost grows as its on-disk size grows. ZAP's daemon session here runs continuously for the
     * lifetime of the container; after hours of scanning many targets/subdomains with no session
     * boundary ever drawn, the History table had grown large enough to make individual inserts
     * slow enough to hold that global lock long enough for a real backlog to build - and since
     * every new spidered/scanned message needs the same lock to log itself, the backlog only
     * grows under continued load, never drains, and any API caller (spidering, scanning, or our
     * own alerts/numberOfMessages reads) queues up behind it.
     *
     * <p>Starting a genuinely fresh, empty session at the top of every job bounds the History
     * table to roughly one job's own traffic (hundreds of rows) rather than letting it accumulate
     * across this ZAP instance's entire uptime - HSQLDB's cache never has the chance to grow large
     * enough to hit the slow-eviction regime in the first place. Safe to do unconditionally here
     * (not just opportunistically): {@code ScanJobRepository#claim}'s ZAP_ACTIVE_SCAN concurrency
     * cap already guarantees at most one {@link #runFullScan} executes at a time system-wide, so
     * there is never a concurrent job whose in-progress session data this could clobber. Best-effort,
     * same reasoning as {@link #disableNoiseScanners}: a failed reset costs one job's worth of
     * extra accumulated history, not a wrong or lost finding, and isn't worth failing the scan over
     * - especially since the whole point is resilience against ZAP itself being unhealthy.
     */
    private void startFreshSession() {
        try {
            call("/JSON/core/action/newSession/", Map.of("name", "", "overwrite", "true"));
        } catch (ScanModuleException e) {
            log.warn("could not start a fresh ZAP session before this scan - history may carry over from prior runs: {}", e.getMessage());
        }
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
        // Confirmed live (via the logging added below, against example.co.uk's own real apex -
        // 129 messages, 1 io error): requiring ioErrorCount == 0 was too strict. A real,
        // content-rich site pulling in third-party widgets (this one embeds Trustpilot, Vimeo,
        // Facebook Connect - confirmed via a separate crawl) will often have exactly one slow or
        // broken embedded resource among hundreds of otherwise-successful requests; that single
        // incidental failure was silently discarding the entire legitimate crawl (and any ascan
        // findings that would have followed) rather than just being noise. Every genuinely dead
        // host seen this session instead shows ioErrorCount == messageCount (every single
        // request failed, e.g. 3/3) - "not every message failed" is the threshold that actually
        // separates "real site, one broken embed" from "nothing here at all", not "zero errors".
        boolean reachable = messageCount > 0 && ioErrorCount < messageCount;
        if (!reachable) {
            log.warn("ZAP spider found nothing reachable at {}: messageCount={} ioErrorCount={}",
                    targetUrl, messageCount, ioErrorCount);
        } else if (ioErrorCount > 0) {
            log.info("ZAP spider against {} had {} incidental io error(s) out of {} messages - proceeding, not treating as unreachable",
                    targetUrl, ioErrorCount, messageCount);
        }
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
        String body = callRaw(path, params, DEFAULT_CALL_TIMEOUT);
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            throw new ScanModuleException("failed to parse ZAP response from " + path + ": " + body, e);
        }
    }

    private String callRaw(String path, Map<String, String> params) throws ScanModuleException {
        return callRaw(path, params, DEFAULT_CALL_TIMEOUT);
    }

    /**
     * Every other caller hits a lightweight status/action endpoint that answers in milliseconds
     * regardless of scan size - 30s is generous there. The alerts fetch is the one exception:
     * it returns one JSON object per finding across a whole spider+ascan run against a real,
     * possibly large target (this class's own MAX_RESPONSE_BYTES doc comment already notes this),
     * and how long ZAP takes to assemble that response scales with its accumulated alert store,
     * not just this one host - found live: a example.co.uk alerts fetch timed out twice in a row at
     * 30s, on what would have been its final retry attempt (losing every finding from that host's
     * whole ZAP scan, not just a delay), while ZAP's own lightweight status endpoint answered
     * instantly the entire time - so this wasn't ZAP being generally overloaded, just this one
     * disproportionately-heavy call sharing too tight a budget with tiny ones.
     */
    private static final Duration DEFAULT_CALL_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration ALERTS_FETCH_TIMEOUT = Duration.ofSeconds(120);

    private String callRaw(String path, Map<String, String> params, Duration timeout) throws ScanModuleException {
        StringBuilder query = new StringBuilder("apikey=").append(encode(apiKey));
        for (Map.Entry<String, String> entry : params.entrySet()) {
            query.append('&').append(entry.getKey()).append('=').append(encode(entry.getValue()));
        }
        URI uri = URI.create(baseUrl + path + "?" + query);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
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
