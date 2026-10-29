package org.freedonia.bloodhound.worker.modules.http;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Fetch side of the HTTP header check: a single plain GET, no different from
 * a normal browser request - exactly the kind of Tier 1 technique the
 * product's passive-scanning boundary is built around. Tries HTTPS first,
 * falls back to HTTP only to note the lack of TLS if HTTPS fails outright.
 * Redirects are followed manually via SafeHttpGet (SSRF guard: each hop's
 * resolved address is checked before it's requested) rather than the JDK's
 * built-in Redirect.NORMAL, which would happily follow a target's redirect
 * to an internal address with no validation at all.
 */
public class HttpHeaderFetcher {

    private static final int MAX_REDIRECTS = 5;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    /**
     * A fabricated origin, not something any real site would legitimately allowlist - so seeing
     * it echoed back verbatim in Access-Control-Allow-Origin can only mean the server reflects
     * whatever Origin it's sent, not that this exact value happens to be on a real allowlist.
     * {@code .invalid} is the RFC 2606 TLD reserved for exactly this "definitely not a real,
     * resolvable domain" use.
     */
    static final String CORS_PROBE_ORIGIN = "https://bh-cors-probe.invalid";

    /** A distinctive marker header value - if a server's TRACE response echoes the request back (RFC 7231's own documented behavior for this method), this exact string reappearing in the response body confirms it's a genuine loop-back echo, not just any 200 response. */
    static final String TRACE_PROBE_MARKER = "bh-trace-probe-9f3a1c";

    /**
     * Common query-param names a login/logout/SSO flow redirects through after completing - not
     * exhaustive (an app-specific name could always exist), but these cover the overwhelming
     * majority of real-world open-redirect reports. Kept short deliberately: each is one extra GET
     * per hostname, and this module already fans out across up to 40 subdomains per target.
     */
    private static final List<String> OPEN_REDIRECT_PARAMS =
            List.of("redirect", "url", "next", "return", "continue");

    /** Same RFC 2606 "definitely not a real, resolvable domain" reasoning as {@link #CORS_PROBE_ORIGIN} - distinctive enough that this exact substring reappearing in a Location header (see HttpHeaderParser#openRedirectFindings) can only mean the server used this probe's own param value, not an unrelated same-pattern coincidence. */
    static final String OPEN_REDIRECT_PROBE_MARKER = "bh-open-redirect-probe.invalid";

    static final String OPEN_REDIRECT_PROBE_TARGET = "https://" + OPEN_REDIRECT_PROBE_MARKER + "/";

    public FetchResult fetch(String hostname) throws ScanModuleException {
        FetchResult.PlainHttpProbe plainHttp = probePlainHttp(hostname);
        try {
            return toResult(true, hostname, get("https://" + hostname + "/"), plainHttp);
        } catch (Exception httpsFailure) {
            try {
                return toResult(false, hostname, get("http://" + hostname + "/"), plainHttp);
            } catch (Exception httpFailure) {
                throw new ScanModuleException("failed to reach " + hostname + " over HTTPS or HTTP", httpFailure);
            }
        }
    }

    /**
     * One extra GET against the same scheme+host that just answered, carrying a fabricated
     * {@code Origin} header - the question is specifically "does this server echo back whatever
     * Origin it's handed" (a credentialed cross-origin request forgery enabler), which reading
     * the main fetch's own (no Origin header sent) response can never answer. Best-effort: a
     * failure here just means no CORS evidence, not a whole-module failure - the main fetch
     * already succeeded, which is the part every other header check here depends on.
     */
    private FetchResult.CorsProbe probeCors(boolean https, String hostname) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create((https ? "https://" : "http://") + hostname + "/"))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScanUserAgent.VALUE)
                    .header("Origin", CORS_PROBE_ORIGIN)
                    .GET()
                    .build();
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return new FetchResult.CorsProbe(
                    response.headers().firstValue("access-control-allow-origin").orElse(null),
                    response.headers().firstValue("access-control-allow-credentials").orElse(null));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * One GET to {@code http://host/} with NO redirect following - the question is precisely
     * "what does the first cleartext response do", which the redirect-following {@link #get}
     * can't answer (it either lands on the final page or throws). Null when nothing answers
     * on port 80: not serving cleartext at all is the ideal, not a finding. Connects to the
     * same hostname the HTTPS fetch validates, via the same SafeAddressValidator gate.
     */
    private FetchResult.PlainHttpProbe probePlainHttp(String hostname) {
        try {
            SafeAddressValidator.requireSafeIfResolvable(hostname);
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + hostname + "/"))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScanUserAgent.VALUE)
                    .GET()
                    .build();
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return new FetchResult.PlainHttpProbe(
                    response.statusCode(), response.headers().firstValue("location").orElse(null));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * One TRACE request against the same scheme+host that just answered - the question is
     * specifically "does this server process TRACE at all" (RFC 7231 2.1: a server SHOULD NOT
     * support it on an externally-facing endpoint, since it enables Cross-Site Tracing in
     * combination with other vulnerabilities), which reading the main GET's own response can
     * never answer. {@code BodyHandlers.ofString()} (not {@code discarding()}, unlike every other
     * probe in this class) specifically so {@code echoedMarker} can confirm the response is a
     * genuine echo-back, not just coincidentally a 200 - capped the same way SafeHttpGet's own
     * capped reads are, since this body is attacker-influenceable like any other target response.
     * Best-effort: a failure here just means no TRACE evidence, not a whole-module failure.
     */
    private FetchResult.TraceProbe probeTraceMethod(boolean https, String hostname) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create((https ? "https://" : "http://") + hostname + "/"))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScanUserAgent.VALUE)
                    .header("X-Bh-Trace-Probe", TRACE_PROBE_MARKER)
                    .method("TRACE", HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<java.io.InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            String body = SafeHttpGet.readCappedUtf8(response.body(), 10_000);
            return new FetchResult.TraceProbe(response.statusCode(), body.contains(TRACE_PROBE_MARKER));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * One GET per candidate param name (see {@link #OPEN_REDIRECT_PARAMS}), stopping at the first
     * one that comes back with any 3xx + Location header at all - whether that Location is
     * actually off-host (a real open redirect) vs. this param name coincidentally mapping to some
     * other in-site redirect is a decision for HttpHeaderParser, not this raw-capture fetch step.
     * {@code Redirect.NEVER} on the shared client (set at class level) means the raw 3xx + Location
     * is read directly, never silently followed. Best-effort per param: a failure just means try
     * the next name, not a whole-module failure - the main fetch already succeeded.
     */
    private FetchResult.OpenRedirectProbe probeOpenRedirect(boolean https, String hostname) {
        String encodedTarget = URLEncoder.encode(OPEN_REDIRECT_PROBE_TARGET, StandardCharsets.UTF_8);
        for (String param : OPEN_REDIRECT_PARAMS) {
            try {
                String url = (https ? "https://" : "http://") + hostname + "/?" + param + "=" + encodedTarget;
                HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(8))
                        .header("User-Agent", ScanUserAgent.VALUE)
                        .GET()
                        .build();
                HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
                String location = response.headers().firstValue("location").orElse(null);
                if (response.statusCode() >= 300 && response.statusCode() < 400 && location != null) {
                    return new FetchResult.OpenRedirectProbe(param, location);
                }
            } catch (Exception ignored) {
                // this param name's probe failed outright - try the next one
            }
        }
        return null;
    }

    private HttpResponse<Void> get(String url) throws IOException, InterruptedException {
        return SafeHttpGet.get(
                client,
                url,
                Duration.ofSeconds(8),
                ScanUserAgent.VALUE,
                HttpResponse.BodyHandlers.discarding(),
                MAX_REDIRECTS);
    }

    private FetchResult toResult(
            boolean https, String hostname, HttpResponse<Void> response, FetchResult.PlainHttpProbe plainHttp) {
        Map<String, String> headers = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) {
                headers.put(name.toLowerCase(), values.get(0));
            }
        });
        FetchResult.CorsProbe cors = probeCors(https, hostname);
        FetchResult.TraceProbe trace = probeTraceMethod(https, hostname);
        FetchResult.OpenRedirectProbe openRedirect = probeOpenRedirect(https, hostname);
        return new FetchResult(
                https, headers, response.headers().allValues("set-cookie"), plainHttp, cors, trace, openRedirect);
    }
}
