package org.freedonia.bloodhound.worker.modules.exposure;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.worker.ratelimit.HostnameRateLimiter;

/**
 * Fetch side of the exposure-checks module: ~20 independent, plain
 * HTTP GET/POST probes (equivalent to browser requests, genuinely passive
 * per the Tier 1 boundary) plus one raw-socket Redis INFO probe, run with
 * bounded concurrency. No interpretation here - see
 * {@link ExposedPathDecisionLogic}.
 */
public class ExposedPathFetcher {

    /** Bounds how much of a response body we ever hold in memory - enough to find a JSON marker near the start, never a full multi-MB dump. */
    static final int BODY_LIMIT_BYTES = 65_536;

    private static final int PARALLELISM = 8;
    private static final int DEFAULT_PORT_CONNECT_TIMEOUT_S = 5;
    private static final int ALT_PORT_CONNECT_TIMEOUT_S = 3;
    private static final int REQUEST_TIMEOUT_S = 6;

    /** Every check except Redis (handled separately - it isn't HTTP). Bounded, deliberately not expanded beyond this list for Phase 1. */
    static final List<ExposureProbeSpec> CATALOG = List.of(
            ExposureProbeSpec.getNoBody("EXPOSURE_ACTUATOR_HEAPDUMP", List.of("/actuator/heapdump")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_ENV", List.of("/actuator/env")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_BEANS", List.of("/actuator/beans")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_MAPPINGS", List.of("/actuator/mappings")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_CONFIGPROPS", List.of("/actuator/configprops")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_THREADDUMP", List.of("/actuator/threaddump")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_LOGGERS", List.of("/actuator/loggers")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_INDEX", List.of("/actuator")),
            ExposureProbeSpec.get("EXPOSURE_GIT_CONFIG", List.of("/.git/config")),
            ExposureProbeSpec.get("EXPOSURE_ENV_FILE", List.of("/.env")),
            ExposureProbeSpec.get("EXPOSURE_AWS_CREDENTIALS", List.of("/.aws/credentials")),
            ExposureProbeSpec.get("EXPOSURE_SWAGGER_UI", List.of("/v2/api-docs", "/v3/api-docs")),
            ExposureProbeSpec.post("EXPOSURE_GRAPHQL_INTROSPECTION", "/graphql", "{\"query\":\"{__schema{types{name}}}\"}"),
            ExposureProbeSpec.get("EXPOSURE_PHPMYADMIN", List.of("/phpmyadmin/", "/phpMyAdmin/")),
            ExposureProbeSpec.get("EXPOSURE_JENKINS_SCRIPT", List.of("/script")),
            ExposureProbeSpec.get("EXPOSURE_KIBANA_UNAUTH", List.of("/app/kibana")),
            ExposureProbeSpec.get("EXPOSURE_SECURITY_TXT_PRESENT", List.of("/.well-known/security.txt")),
            ExposureProbeSpec.altPort("EXPOSURE_DOCKER_API", "/version", 2375),
            ExposureProbeSpec.altPort("EXPOSURE_ELASTICSEARCH_UNAUTH", "/", 9200),
            ExposureProbeSpec.altPort("EXPOSURE_CONSUL_UNAUTH", "/v1/status/leader", 8500));

    public ExposedPathFetchResult fetch(String hostname) {
        ProbeResponse baseline =
                probe(hostname, "/__bloodhound_probe_nonexistent_" + UUID.randomUUID() + "__", "GET", null, null, false);

        Map<String, ProbeResponse> responses = new ConcurrentHashMap<>();
        ExecutorService pool = Executors.newFixedThreadPool(PARALLELISM);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (ExposureProbeSpec spec : CATALOG) {
                futures.add(pool.submit(() -> responses.put(spec.ruleId(), fetchFirstMatch(hostname, spec))));
            }
            for (Future<?> f : futures) {
                try {
                    f.get(30, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                    // leaves that probe's entry absent from the map; decision logic treats a missing entry as "no finding"
                }
            }
        } finally {
            pool.shutdownNow();
        }

        String redisResponse = probeRedis(hostname);
        return new ExposedPathFetchResult(baseline, responses, redisResponse);
    }

    private ProbeResponse fetchFirstMatch(String hostname, ExposureProbeSpec spec) {
        ProbeResponse last = ProbeResponse.unreachable();
        for (String path : spec.paths()) {
            ProbeResponse r = probe(hostname, path, spec.method(), spec.postBody(), spec.altPort(), spec.skipBody());
            if (r.status() == 200) {
                return r;
            }
            last = r;
        }
        return last;
    }

    private ProbeResponse probe(
            String hostname, String path, String method, String postBody, Integer altPort, boolean skipBody) {
        HostnameRateLimiter.shared().acquire(hostname);
        boolean isAltPort = altPort != null;
        URI uri = isAltPort ? URI.create("http://" + hostname + ":" + altPort + path) : URI.create("https://" + hostname + path);
        try {
            return doProbe(uri, method, postBody, skipBody, isAltPort);
        } catch (Exception httpsFailure) {
            if (isAltPort) {
                return ProbeResponse.unreachable();
            }
            // Default-port probes fall back to plain HTTP only on a connection-level failure, matching
            // HttpHeaderFetcher's existing HTTPS-first-then-HTTP pattern for reaching a target at all.
            try {
                return doProbe(URI.create("http://" + hostname + path), method, postBody, skipBody, false);
            } catch (Exception httpFailure) {
                return ProbeResponse.unreachable();
            }
        }
    }

    private ProbeResponse doProbe(URI uri, String method, String postBody, boolean skipBody, boolean isAltPort)
            throws IOException, InterruptedException {
        // Unlike every other target-facing fetcher in this module (HttpHeaderFetcher/TechFetcher/
        // DocumentFetcher via SafeHttpGet, NucleiFetcher/CloudBucketChecker directly), this class makes
        // ~21 independent connections per host by hostname string rather than a pre-resolved address, and
        // HostFanOut's one SafeAddressValidator check happens well before any of them - so without a check
        // here too, a target whose DNS flips after that one check (TTL=0 rebinding) would sail every one of
        // these connections straight past the SSRF guard. Matches the same single check-then-connect
        // pattern the rest of the codebase already accepts as its baseline (see SafeHttpGet's javadoc for
        // the residual TOCTOU gap that pattern doesn't fully close).
        SafeAddressValidator.requireSafeIfResolvable(uri.getHost());
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(isAltPort ? ALT_PORT_CONNECT_TIMEOUT_S : DEFAULT_PORT_CONNECT_TIMEOUT_S))
                .build();
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(REQUEST_TIMEOUT_S))
                .header("User-Agent", "Bloodhound-ASM/1.0 (+passive surface scan)");
        if ("POST".equals(method)) {
            builder.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(postBody));
        } else {
            builder.GET();
        }

        if (skipBody) {
            HttpResponse<Void> response = client.send(builder.build(), HttpResponse.BodyHandlers.discarding());
            return new ProbeResponse(
                    response.statusCode(),
                    response.headers().firstValue("content-type").orElse(null),
                    contentLength(response),
                    "");
        }

        HttpResponse<InputStream> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        byte[] buf = new byte[BODY_LIMIT_BYTES];
        int read;
        try (InputStream is = response.body()) {
            read = is.readNBytes(buf, 0, buf.length);
        }
        String body = new String(buf, 0, read, StandardCharsets.UTF_8);
        return new ProbeResponse(
                response.statusCode(), response.headers().firstValue("content-type").orElse(null), (long) read, body);
    }

    private Long contentLength(HttpResponse<?> response) {
        OptionalLong cl = response.headers().firstValueAsLong("content-length");
        return cl.isPresent() ? cl.getAsLong() : null;
    }

    /**
     * Raw RESP-ish probe: a bare "INFO\r\n" is enough to get a real,
     * unauthenticated Redis server to reply with its bulk-string info blob;
     * an ACL/requirepass-protected server replies with a "-NOAUTH"/"-ERR"
     * line instead, which decision logic treats as a negative (properly
     * secured), not a finding.
     */
    private String probeRedis(String hostname) {
        HostnameRateLimiter.shared().acquire(hostname);
        try (Socket socket = new Socket()) {
            // Same SSRF re-check as doProbe() - this is a raw socket connect by hostname, not HTTP,
            // so it needs its own guard rather than sharing doProbe()'s.
            SafeAddressValidator.requireSafeIfResolvable(hostname);
            socket.connect(new InetSocketAddress(hostname, 6379), ALT_PORT_CONNECT_TIMEOUT_S * 1000);
            socket.setSoTimeout(REQUEST_TIMEOUT_S * 1000);
            socket.getOutputStream().write("INFO\r\n".getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] buf = new byte[4096];
            int read = socket.getInputStream().read(buf);
            if (read <= 0) {
                return null;
            }
            return new String(buf, 0, read, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }
}
