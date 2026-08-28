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
 * Fetch side of cloud-bucket public-listing exposure detection. Same shape
 * as {@link DanglingCnameChecker}: cheap for the overwhelming majority of
 * hostnames (no CNAME, or a CNAME matching no known cloud-storage provider)
 * since {@link CloudBucketDecisionLogic#matchProvider} is a pure local check
 * done before any network call; a confirmation GET only happens for the
 * small subset whose CNAME actually points at a known bucket provider.
 */
class CloudBucketChecker {

    record Result(CloudBucketDecisionLogic.Provider provider, String checkUrl, boolean publiclyListable) {}

    private static final int POOL_SIZE = 10;
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    Map<String, Result> checkAll(Map<String, String> hostnameToCname) {
        if (hostnameToCname.isEmpty()) {
            return Map.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, hostnameToCname.size()));
        try {
            Map<String, Future<Optional<Result>>> futures = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : hostnameToCname.entrySet()) {
                futures.put(entry.getKey(), pool.submit(() -> checkOne(entry.getKey(), entry.getValue())));
            }
            Map<String, Result> results = new LinkedHashMap<>();
            for (Map.Entry<String, Future<Optional<Result>>> entry : futures.entrySet()) {
                try {
                    entry.getValue().get(30, TimeUnit.SECONDS).ifPresent(r -> results.put(entry.getKey(), r));
                } catch (Exception ignored) {
                    // Treated as "no bucket exposure found" for this host - same tolerant
                    // philosophy as DanglingCnameChecker: one host's check timing out
                    // shouldn't be reported as a false positive or fail the whole batch.
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private Optional<Result> checkOne(String hostname, String cnameTarget) {
        Optional<CloudBucketDecisionLogic.Match> match = CloudBucketDecisionLogic.matchProvider(hostname, cnameTarget);
        if (match.isEmpty()) {
            return Optional.empty();
        }
        CappedResponse response = get(match.get().checkUrl());
        if (response == null) {
            return Optional.empty();
        }
        boolean listable = CloudBucketDecisionLogic.isPubliclyListable(response.statusCode(), response.body());
        return Optional.of(new Result(match.get().provider(), match.get().checkUrl(), listable));
    }

    private record CappedResponse(int statusCode, String body) {}

    /** A bucket-listing response only needs enough to see whether it looks like a directory listing - not the full (potentially huge, for a truly public bucket) object list. */
    private static final int BODY_CHAR_CAP = 300_000;

    private CappedResponse get(String url) {
        try {
            URI uri = URI.create(url);
            // SSRF guard: this URL's host is a bucket endpoint derived from a discovered
            // subdomain's CNAME, never validated the way a user-submitted target hostname
            // is - see SafeAddressValidator's javadoc.
            SafeAddressValidator.requireSafeIfResolvable(uri.getHost());
            HttpRequest request =
                    HttpRequest.newBuilder(uri).timeout(TIMEOUT).header("User-Agent", ScanUserAgent.VALUE).GET().build();
            // ofInputStream()+readCappedUtf8, not ofString(): a security review found ofString()
            // buffers the ENTIRE response into memory with no size limit - a scanned target
            // could stream gigabytes within the request timeout and exhaust the shared worker
            // JVM's heap.
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            return new CappedResponse(response.statusCode(), SafeHttpGet.readCappedUtf8(response.body(), BODY_CHAR_CAP));
        } catch (Exception e) {
            return null;
        }
    }
}
