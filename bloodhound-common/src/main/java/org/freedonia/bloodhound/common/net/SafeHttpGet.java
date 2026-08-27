package org.freedonia.bloodhound.common.net;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * GET with manually-followed, SSRF-guarded redirects: every hop's host is
 * resolved and checked against {@link SafeAddressValidator} before the
 * request for it is sent. Without this, a scanned target - which is by
 * definition attacker-influenceable, since it's whatever hostname a user
 * (or a compromised/malicious "competitor" domain someone is tracking) has
 * pointed this at - could 30x-redirect a fetch toward 169.254.169.254 or an
 * internal Docker-network address, and the response would flow straight into
 * findings/evidence data as if it came from the target itself. The client
 * passed in must have {@code Redirect.NEVER} configured; redirect handling
 * happens entirely here, one validated hop at a time.
 *
 * <p>This closes the practical exploit path (a target's DNS answering with a
 * safe address at redirect time) but is not a full DNS-rebinding defense:
 * the validation lookup here and the connection {@link HttpClient#send} does
 * internally are two separate resolutions a few milliseconds apart, so a
 * TTL=0 attacker DNS server could in principle answer differently between
 * them. Fully closing that would mean pinning the exact validated IP for the
 * actual connection (not supported by the JDK's HttpClient without a custom
 * connector) - flagged as a known residual gap, not silently claimed as solved.
 */
public final class SafeHttpGet {

    private SafeHttpGet() {}

    public static <T> HttpResponse<T> get(
            HttpClient client,
            String url,
            Duration requestTimeout,
            String userAgent,
            HttpResponse.BodyHandler<T> bodyHandler,
            int maxRedirects)
            throws IOException, InterruptedException {
        String currentUrl = url;
        for (int hop = 0; hop <= maxRedirects; hop++) {
            URI uri = URI.create(currentUrl);
            requireSafeHost(uri.getHost());
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(requestTimeout)
                    .header("User-Agent", userAgent)
                    .GET()
                    .build();
            HttpResponse<T> response = client.send(request, bodyHandler);
            int status = response.statusCode();
            if (status < 300 || status >= 400) {
                return response;
            }
            Optional<String> location = response.headers().firstValue("location");
            if (location.isEmpty()) {
                return response;
            }
            currentUrl = uri.resolve(location.get()).toString();
        }
        throw new IOException("exceeded " + maxRedirects + " redirects following " + url);
    }

    /**
     * A response together with the union of every hop's headers along the
     * way, not just the final destination's - lowercased, later hops
     * overwriting earlier ones on key conflict. {@link #get} discards
     * intermediate-hop headers entirely, which is right for its callers
     * (they want the final page), but a redirect response can itself carry
     * a genuine fingerprinting signal a scanner cares about - confirmed for
     * real against a live target: WordPress's canonical-URL redirect sets
     * {@code X-Redirect-By: WordPress} on the 301 itself, a strong signal
     * that never appears anywhere in the final destination page's own
     * headers or body.
     */
    public record RedirectChainResult<T>(HttpResponse<T> response, Map<String, String> allHopHeaders) {}

    public static <T> RedirectChainResult<T> getWithRedirectChainHeaders(
            HttpClient client,
            String url,
            Duration requestTimeout,
            String userAgent,
            HttpResponse.BodyHandler<T> bodyHandler,
            int maxRedirects)
            throws IOException, InterruptedException {
        Map<String, String> allHopHeaders = new LinkedHashMap<>();
        String currentUrl = url;
        for (int hop = 0; hop <= maxRedirects; hop++) {
            URI uri = URI.create(currentUrl);
            requireSafeHost(uri.getHost());
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(requestTimeout)
                    .header("User-Agent", userAgent)
                    .GET()
                    .build();
            HttpResponse<T> response = client.send(request, bodyHandler);
            response.headers().map().forEach((name, values) -> {
                if (!values.isEmpty()) {
                    allHopHeaders.put(name.toLowerCase(), values.get(0));
                }
            });
            int status = response.statusCode();
            if (status < 300 || status >= 400) {
                return new RedirectChainResult<>(response, allHopHeaders);
            }
            Optional<String> location = response.headers().firstValue("location");
            if (location.isEmpty()) {
                return new RedirectChainResult<>(response, allHopHeaders);
            }
            currentUrl = uri.resolve(location.get()).toString();
        }
        throw new IOException("exceeded " + maxRedirects + " redirects following " + url);
    }

    /**
     * Reads at most {@code maxBytes} from {@code body}, decoded as UTF-8, and closes the
     * stream - the capped-read counterpart to fetching with {@code BodyHandlers.ofInputStream()}
     * instead of {@code ofString()}. A security review flagged that {@code ofString()} buffers
     * the ENTIRE response into memory with no size limit before any caller-side truncation ever
     * runs (found live: {@code TechFetcher} truncated to a char cap, but only after {@code
     * ofString()} had already fully buffered the untruncated body) - a scanned target, attacker-
     * influenceable by definition (see this class's own javadoc), could stream gigabytes within
     * the request timeout and exhaust the shared worker JVM's heap, affecting every other org's
     * queued scans on that worker, with zero authorization required since Tier 1 scanning runs
     * against any tracked competitor/watchlist domain. {@link InputStream#readNBytes(int)}
     * itself is what bounds memory here: it never allocates more than {@code maxBytes}
     * regardless of how much more the server tries to send, and truncates silently rather than
     * throwing past the cap - a partial page is still useful for parsing (generator meta tags,
     * titles, etc. are typically near the top), unlike discarding everything.
     */
    public static String readCappedUtf8(InputStream body, int maxBytes) throws IOException {
        try (InputStream in = body) {
            return new String(in.readNBytes(maxBytes), StandardCharsets.UTF_8);
        }
    }

    private static void requireSafeHost(String host) throws IOException {
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new IOException("could not resolve " + host, e);
        }
        for (InetAddress address : addresses) {
            if (SafeAddressValidator.isUnsafeToConnect(address)) {
                throw new IOException(
                        "refusing to connect to " + host + " - resolves to a private/loopback/reserved address");
            }
        }
    }
}
