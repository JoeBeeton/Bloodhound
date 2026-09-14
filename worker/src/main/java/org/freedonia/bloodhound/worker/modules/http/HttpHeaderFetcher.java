package org.freedonia.bloodhound.worker.modules.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
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

    public FetchResult fetch(String hostname) throws ScanModuleException {
        FetchResult.PlainHttpProbe plainHttp = probePlainHttp(hostname);
        try {
            return toResult(true, get("https://" + hostname + "/"), plainHttp);
        } catch (Exception httpsFailure) {
            try {
                return toResult(false, get("http://" + hostname + "/"), plainHttp);
            } catch (Exception httpFailure) {
                throw new ScanModuleException("failed to reach " + hostname + " over HTTPS or HTTP", httpFailure);
            }
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

    private HttpResponse<Void> get(String url) throws IOException, InterruptedException {
        return SafeHttpGet.get(
                client,
                url,
                Duration.ofSeconds(8),
                ScanUserAgent.VALUE,
                HttpResponse.BodyHandlers.discarding(),
                MAX_REDIRECTS);
    }

    private FetchResult toResult(boolean https, HttpResponse<Void> response, FetchResult.PlainHttpProbe plainHttp) {
        Map<String, String> headers = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) {
                headers.put(name.toLowerCase(), values.get(0));
            }
        });
        return new FetchResult(https, headers, response.headers().allValues("set-cookie"), plainHttp);
    }
}
