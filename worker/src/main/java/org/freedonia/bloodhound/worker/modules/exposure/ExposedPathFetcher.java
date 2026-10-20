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
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
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

    /**
     * Accept-all, scoped to this file's one altPortHttps=true probe (Kubernetes), where "can we
     * read the body at all" is the only question, not chain trust. Deliberately an
     * X509ExtendedTrustManager, not the plain 3-method X509TrustManager TlsFetcher's own
     * PERMISSIVE_TRUST_MANAGER uses: TlsFetcher talks to a raw SSLSocket directly, but
     * java.net.http.HttpClient wraps a plain X509TrustManager in its own
     * AbstractTrustManagerWrapper, which performs a MANDATORY hostname/identity check
     * unconditionally - confirmed live before writing this (a self-signed, IP-only cert was
     * rejected with "No subject alternative names present" even with a fully-permissive plain
     * X509TrustManager AND SSLParameters.setEndpointIdentificationAlgorithm(null) on the client).
     * Only the extended interface's socket/engine overloads bypass that wrapper entirely.
     */
    private static final X509ExtendedTrustManager PERMISSIVE_TRUST_MANAGER = new X509ExtendedTrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    /** Every check except Redis (handled separately - it isn't HTTP). Bounded, deliberately not expanded beyond this list for Phase 1. */
    static final List<ExposureProbeSpec> CATALOG = List.of(
            ExposureProbeSpec.getNoBody("EXPOSURE_ACTUATOR_HEAPDUMP", List.of("/actuator/heapdump")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_ENV", List.of("/actuator/env")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_BEANS", List.of("/actuator/beans")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_MAPPINGS", List.of("/actuator/mappings")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_CONFIGPROPS", List.of("/actuator/configprops")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_THREADDUMP", List.of("/actuator/threaddump")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_LOGGERS", List.of("/actuator/loggers")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_HEALTH", List.of("/actuator/health")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_INFO", List.of("/actuator/info")),
            ExposureProbeSpec.get("EXPOSURE_ACTUATOR_INDEX", List.of("/actuator")),
            ExposureProbeSpec.get("EXPOSURE_GIT_CONFIG", List.of("/.git/config")),
            // Subversion's own equivalent of the Git check above - a standard pairing in most
            // scanners (Nikto checks both). Pre-1.7 SVN working copies keep a plain-text entries
            // file per directory disclosing the full repository URL and revision metadata;
            // 1.7+ instead uses a SQLite database (.svn/wc.db) this check doesn't attempt to
            // fingerprint, so this only catches older working copies - still a real, if shrinking,
            // population given how long unmaintained legacy deployments stay online.
            ExposureProbeSpec.get("EXPOSURE_SVN_ENTRIES", List.of("/.svn/entries")),
            // Beyond the bare ".env" this already covered, modern framework tooling (Next.js,
            // Create React App, Vite, Django) commonly layers environment-specific files on top -
            // each one just as likely to be accidentally included in a deployed build artifact.
            ExposureProbeSpec.get(
                    "EXPOSURE_ENV_FILE",
                    List.of(
                            "/.env", "/.env.local", "/.env.production", "/.env.development",
                            "/.env.production.local")),
            ExposureProbeSpec.get("EXPOSURE_AWS_CREDENTIALS", List.of("/.aws/credentials")),
            ExposureProbeSpec.get("EXPOSURE_SWAGGER_UI", List.of("/v2/api-docs", "/v3/api-docs")),
            ExposureProbeSpec.post("EXPOSURE_GRAPHQL_INTROSPECTION", "/graphql", "{\"query\":\"{__schema{types{name}}}\"}"),
            ExposureProbeSpec.get("EXPOSURE_PHPMYADMIN", List.of("/phpmyadmin/", "/phpMyAdmin/")),
            ExposureProbeSpec.get("EXPOSURE_JENKINS_SCRIPT", List.of("/script")),
            ExposureProbeSpec.get("EXPOSURE_KIBANA_UNAUTH", List.of("/app/kibana")),
            ExposureProbeSpec.get("EXPOSURE_SECURITY_TXT_PRESENT", List.of("/.well-known/security.txt")),
            ExposureProbeSpec.get("EXPOSURE_DS_STORE", List.of("/.DS_Store")),
            ExposureProbeSpec.get(
                    "EXPOSURE_DIRECTORY_LISTING",
                    List.of("/backup/", "/backups/", "/uploads/", "/files/", "/old/", "/tmp/", "/logs/", "/assets/", "/images/")),
            ExposureProbeSpec.get(
                    "EXPOSURE_BACKUP_ARCHIVE",
                    List.of("/backup.zip", "/www.zip", "/site.zip", "/backup.tar.gz", "/www.tar.gz")),
            ExposureProbeSpec.get(
                    "EXPOSURE_SQL_DUMP_FILE",
                    List.of("/backup.sql", "/db.sql", "/database.sql", "/dump.sql", "/site.sql")),
            ExposureProbeSpec.get("EXPOSURE_PHP_INFO", List.of("/phpinfo.php", "/info.php", "/php_info.php", "/test.php")),
            ExposureProbeSpec.get("EXPOSURE_SSH_PRIVATE_KEY", List.of("/id_rsa", "/.ssh/id_rsa", "/id_dsa", "/server.key", "/private.key")),
            ExposureProbeSpec.get("EXPOSURE_PROMETHEUS_METRICS", List.of("/metrics")),
            ExposureProbeSpec.get("EXPOSURE_SPRING_BOOT_H2_CONSOLE", List.of("/h2-console", "/h2-console/login.jsp")),
            ExposureProbeSpec.get("EXPOSURE_LARAVEL_TELESCOPE", List.of("/telescope", "/telescope/requests")),
            ExposureProbeSpec.get("EXPOSURE_ASPNET_TRACE_AXD", List.of("/trace.axd")),
            ExposureProbeSpec.get("EXPOSURE_ASPNET_ELMAH", List.of("/elmah.axd")),
            // web.config (classic .NET, XML) and appsettings.json (.NET Core, JSON) are the
            // ecosystem's own equivalent of EXPOSURE_ENV_FILE - both routinely hold connection
            // strings and API keys. Properly-configured IIS blocks web.config from being served
            // as static content via a built-in handler mapping, but a misconfigured reverse
            // proxy/container setup serving a .NET app's whole publish directory as static files
            // has neither that protection nor PHP/Node's convention of treating a leading dot as
            // special.
            ExposureProbeSpec.get("EXPOSURE_DOTNET_CONFIG_FILE", List.of("/web.config", "/appsettings.json")),
            ExposureProbeSpec.get("EXPOSURE_ADMINER", List.of("/adminer.php", "/adminer/index.php", "/adminer/")),
            // WordPress's xmlrpc.php, enabled by default, is a classic hardening item every WP
            // security scanner flags: its system.multicall method lets an attacker attempt
            // thousands of login guesses in a single HTTP request (bypassing simple per-request
            // rate limiting), and pingback.ping can be abused as a server-side request forgery
            // vector to make the site itself probe arbitrary internal/external URLs.
            ExposureProbeSpec.get("EXPOSURE_WORDPRESS_XMLRPC", List.of("/xmlrpc.php")),
            // Distinct from xmlrpc.php above: that's about the RATE a brute-force attacker can
            // guess at, this is about WHICH usernames to guess. WordPress's REST API users
            // endpoint is enabled by default and, unless a hardening plugin/config restricts it,
            // lists every registered account's slug (often the real login username) and display
            // name to anyone, unauthenticated - a classic WPScan/Wordfence-flagged info
            // disclosure that directly feeds credential-stuffing and brute-force attacks.
            ExposureProbeSpec.get("EXPOSURE_WORDPRESS_USER_ENUMERATION", List.of("/wp-json/wp/v2/users")),
            ExposureProbeSpec.altPort("EXPOSURE_DOCKER_API", "/version", 2375),
            // 2376 is Docker's TLS-secured daemon port - a real, documented misconfiguration
            // (--tls set without --tlsverify, or a server cert issued with no client-CA check)
            // leaves the full API reachable to anyone who can complete a TLS handshake at all,
            // invisible to the 2375 (plain HTTP) check above.
            ExposureProbeSpec.altPortHttps("EXPOSURE_DOCKER_API_TLS", "/version", 2376),
            ExposureProbeSpec.altPort("EXPOSURE_ELASTICSEARCH_UNAUTH", "/", 9200),
            ExposureProbeSpec.altPort("EXPOSURE_CONSUL_UNAUTH", "/v1/status/leader", 8500),
            ExposureProbeSpec.altPort("EXPOSURE_GRAFANA_UNAUTH", "/api/health", 3000),
            ExposureProbeSpec.altPort("EXPOSURE_MONGO_EXPRESS_UNAUTH", "/", 8081),
            ExposureProbeSpec.altPort("EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH", "/api/rawdata", 8080),
            // Jenkins's Groovy script console (/script), unauthenticated, is full remote code
            // execution - run arbitrary Groovy, which can shell out, on the Jenkins host. A
            // classic, heavily-flagged misconfiguration (Shodan/Censys dorks and Nuclei templates
            // both target it directly) that every major commercial/OSS scanner checks for.
            ExposureProbeSpec.altPort("EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH", "/script", 8080),
            ExposureProbeSpec.altPortHttps("EXPOSURE_KUBERNETES_API_UNAUTH", "/api/v1/namespaces", 6443),
            ExposureProbeSpec.get("EXPOSURE_APACHE_SERVER_STATUS", List.of("/server-status", "/server-status/")),
            ExposureProbeSpec.get("EXPOSURE_NGINX_STUB_STATUS", List.of("/nginx_status", "/status", "/basic_status")));

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
        Map<String, ProbeResponse> sourceMapResponses = fetchSourceMapCandidates(hostname);
        return new ExposedPathFetchResult(baseline, responses, redisResponse, sourceMapResponses);
    }

    /** Same-host {@code <script src>} URLs referenced by the homepage, capped and bounded - the input to EXPOSURE_JS_SOURCE_MAP. */
    private static final Pattern SCRIPT_SRC_PATTERN = Pattern.compile("(?i)<script\\b[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']");
    private static final int MAX_SOURCE_MAP_PROBES = 6;

    /**
     * Unlike every other check in this class, a source map isn't reachable at a fixed, guessable
     * path - modern bundlers (Next.js, webpack, Vite) emit a content-hashed filename per build, so
     * the only way to find one is to fetch the homepage, read which JS files it actually
     * references, and check whether each one's own ".map" counterpart is also publicly served.
     * Same-host only (never follows a script src to a different origin - that's a CDN/third-party
     * script, not this target's own build output, and fetching it would be exactly the kind of
     * SSRF-adjacent "connect wherever a response on this page happens to point" this codebase's
     * same-host discipline exists to avoid), and bounded to MAX_SOURCE_MAP_PROBES distinct scripts
     * so a page with dozens of chunks doesn't balloon this module's request count.
     */
    private Map<String, ProbeResponse> fetchSourceMapCandidates(String hostname) {
        ProbeResponse homepage = probe(hostname, "/", "GET", null, null, false);
        if (homepage.body() == null || homepage.url() == null) {
            return Map.of();
        }
        Set<String> scriptUrls = extractSameHostScriptUrls(hostname, homepage.url(), homepage.body());
        if (scriptUrls.isEmpty()) {
            return Map.of();
        }
        Map<String, ProbeResponse> results = new ConcurrentHashMap<>();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(4, scriptUrls.size()));
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (String scriptUrl : scriptUrls) {
                futures.add(pool.submit(() -> results.put(scriptUrl, probeAbsoluteUrl(scriptUrl + ".map"))));
            }
            for (Future<?> f : futures) {
                try {
                    f.get(15, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                    // leaves that script's entry absent; decision logic treats a missing entry as "no finding"
                }
            }
        } finally {
            pool.shutdownNow();
        }
        return results;
    }

    private static Set<String> extractSameHostScriptUrls(String hostname, String homepageUrl, String body) {
        URI base = URI.create(homepageUrl);
        Set<String> result = new LinkedHashSet<>();
        Matcher m = SCRIPT_SRC_PATTERN.matcher(body);
        while (m.find() && result.size() < MAX_SOURCE_MAP_PROBES) {
            String src = m.group(1);
            if (src.startsWith("data:")) {
                continue;
            }
            try {
                URI resolved = base.resolve(src);
                if (hostname.equalsIgnoreCase(resolved.getHost())
                        && resolved.getPath() != null
                        && resolved.getPath().endsWith(".js")) {
                    result.add(resolved.toString());
                }
            } catch (Exception ignored) {
                // an unparseable src attribute just isn't probed - not fatal to the rest of the page
            }
        }
        return result;
    }

    private ProbeResponse probeAbsoluteUrl(String url) {
        URI uri = URI.create(url);
        HostnameRateLimiter.shared().acquire(uri.getHost());
        try {
            return doProbe(uri, "GET", null, false, false);
        } catch (Exception e) {
            return ProbeResponse.unreachable();
        }
    }

    private ProbeResponse fetchFirstMatch(String hostname, ExposureProbeSpec spec) {
        ProbeResponse last = ProbeResponse.unreachable();
        for (String path : spec.paths()) {
            ProbeResponse r = probe(
                    hostname, path, spec.method(), spec.postBody(), spec.altPort(), spec.altPortHttps(), spec.skipBody());
            if (r.status() == 200) {
                return r;
            }
            last = r;
        }
        return last;
    }

    private ProbeResponse probe(
            String hostname, String path, String method, String postBody, Integer altPort, boolean skipBody) {
        return probe(hostname, path, method, postBody, altPort, false, skipBody);
    }

    private ProbeResponse probe(
            String hostname,
            String path,
            String method,
            String postBody,
            Integer altPort,
            boolean altPortHttps,
            boolean skipBody) {
        HostnameRateLimiter.shared().acquire(hostname);
        boolean isAltPort = altPort != null;
        String scheme = isAltPort && altPortHttps ? "https" : isAltPort ? "http" : "https";
        URI uri = isAltPort ? URI.create(scheme + "://" + hostname + ":" + altPort + path) : URI.create("https://" + hostname + path);
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
        HttpClient.Builder clientBuilder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(isAltPort ? ALT_PORT_CONNECT_TIMEOUT_S : DEFAULT_PORT_CONNECT_TIMEOUT_S));
        // The Kubernetes API server (the one altPortHttps=true entry in this catalog) almost never
        // has its cluster CA in any public trust store - a real cluster's own operator-generated CA
        // is self-signed by design. Unlike the default-port path above (where a non-trusting
        // handshake failure is one of two real signals this module cares about - see
        // HttpHeaderFetcher's own equivalent reasoning), this is purely "can we read the response
        // body at all," so a permissive trust manager here doesn't throw away any signal.
        if (isAltPort && "https".equals(uri.getScheme())) {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[] {PERMISSIVE_TRUST_MANAGER}, new SecureRandom());
                clientBuilder.sslContext(ctx);
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException("TLS unavailable in this JVM", e);
            }
        }
        HttpClient client = clientBuilder.build();
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(REQUEST_TIMEOUT_S))
                .header("User-Agent", ScanUserAgent.VALUE);
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
                    "",
                    uri.toString());
        }

        HttpResponse<InputStream> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        byte[] buf = new byte[BODY_LIMIT_BYTES];
        int read;
        try (InputStream is = response.body()) {
            read = is.readNBytes(buf, 0, buf.length);
        }
        String body = new String(buf, 0, read, StandardCharsets.UTF_8);
        return new ProbeResponse(
                response.statusCode(), response.headers().firstValue("content-type").orElse(null), (long) read, body, uri.toString());
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
            // so it needs its own guard rather than sharing doProbe()'s. resolveSafeAddress, not
            // requireSafeIfResolvable + a hostname-based InetSocketAddress: connecting to the one
            // already-validated address (rather than letting the socket re-resolve the hostname
            // independently) closes the DNS-rebinding TOCTOU window a security review flagged here -
            // no SNI/hostname-verification concerns to preserve, unlike TlsFetcher, since this is a
            // plain TCP connection.
            java.net.InetAddress resolved = SafeAddressValidator.resolveSafeAddress(hostname);
            socket.connect(new InetSocketAddress(resolved, 6379), ALT_PORT_CONNECT_TIMEOUT_S * 1000);
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
