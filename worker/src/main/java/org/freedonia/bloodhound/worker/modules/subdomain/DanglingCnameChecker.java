package org.freedonia.bloodhound.worker.modules.subdomain;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;

/**
 * Fetch side of dangling-CNAME detection. Cheap for the overwhelming
 * majority of hostnames (no CNAME, or a CNAME that matches no known
 * provider) since {@link DanglingCnameDecisionLogic#matchProvider} is a pure
 * local check done before any network call; a confirmation HTTP GET only
 * happens for the small subset whose CNAME actually matches one of the
 * known takeover-prone providers.
 */
class DanglingCnameChecker {

    record Result(String cnameTarget, boolean confirmedDangling, String matchedService) {}

    private static final int POOL_SIZE = 10;
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    Map<String, Result> checkAll(Map<String, String> hostnameToCname) {
        if (hostnameToCname.isEmpty()) {
            return Map.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, hostnameToCname.size()));
        try {
            Map<String, Future<Result>> futures = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : hostnameToCname.entrySet()) {
                futures.put(entry.getKey(), pool.submit(() -> checkOne(entry.getKey(), entry.getValue())));
            }
            Map<String, Result> results = new LinkedHashMap<>();
            for (Map.Entry<String, Future<Result>> entry : futures.entrySet()) {
                try {
                    results.put(entry.getKey(), entry.getValue().get(30, TimeUnit.SECONDS));
                } catch (Exception e) {
                    results.put(entry.getKey(), new Result(hostnameToCname.get(entry.getKey()), false, null));
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private Result checkOne(String hostname, String cnameTarget) {
        Optional<DanglingCnameDecisionLogic.TakeoverService> match =
                DanglingCnameDecisionLogic.matchProvider(cnameTarget);
        if (match.isEmpty()) {
            return new Result(cnameTarget, false, null);
        }
        String body = fetchBody(hostname);
        boolean unclaimed = DanglingCnameDecisionLogic.isUnclaimed(match.get(), body);
        return new Result(cnameTarget, unclaimed, match.get().serviceName());
    }

    private String fetchBody(String hostname) {
        String https = get("https://" + hostname + "/");
        if (https != null) {
            return https;
        }
        return get("http://" + hostname + "/");
    }

    /** A takeover-fingerprint check (e.g. GitHub Pages' "There isn't a GitHub Pages site here") only needs the top of the page, not the whole thing. */
    private static final int BODY_CHAR_CAP = 300_000;

    private String get(String url) {
        try {
            URI uri = URI.create(url);
            // SSRF guard: this URL's host is a discovered subdomain (from
            // crt.sh/subfinder), never validated the way a user-submitted
            // target hostname is - see SafeAddressValidator's javadoc.
            SafeAddressValidator.requireSafeIfResolvable(uri.getHost());
            HttpRequest request =
                    HttpRequest.newBuilder(uri).timeout(TIMEOUT).header("User-Agent", ScanUserAgent.VALUE).GET().build();
            // ofInputStream()+readCappedUtf8, not ofString(): a security review found ofString()
            // buffers the ENTIRE response into memory with no size limit - a scanned target
            // could stream gigabytes within the request timeout and exhaust the shared worker
            // JVM's heap.
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            return SafeHttpGet.readCappedUtf8(response.body(), BODY_CHAR_CAP);
        } catch (Exception e) {
            return null;
        }
    }
}
