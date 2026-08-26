package org.freedonia.bloodhound.common.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
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
