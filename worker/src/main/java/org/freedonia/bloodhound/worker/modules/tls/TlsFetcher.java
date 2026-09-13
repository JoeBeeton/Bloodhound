package org.freedonia.bloodhound.worker.modules.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Raw socket/TLS work for the TLS analysis module - no interpretation, see
 * TlsDecisionLogic for that. Three separate connection attempts:
 *
 * <ol>
 *   <li>A permissive-trust handshake to read the leaf cert's expiry and the
 *       negotiated cipher suite regardless of chain trust.
 *   <li>A default-trust-store handshake solely to determine chainTrusted.
 *   <li>Two probe handshakes restricted to TLSv1 and TLSv1.1 respectively, to
 *       determine legacy-protocol support.
 *   <li>A zgrab2 handshake offering only known-weak cipher suites - see
 *       {@link WeakCipherProbe} for why the JDK can't do this one itself.
 * </ol>
 *
 * <p>Plus a plain HTTPS GET to read the Strict-Transport-Security header.
 */
public class TlsFetcher {

    private static final int PORT = 443;
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final Logger log = LoggerFactory.getLogger(TlsFetcher.class);

    private final WeakCipherProbe weakCipherProbe = new WeakCipherProbe();

    private static final X509TrustManager PERMISSIVE_TRUST_MANAGER = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    public TlsFetchResult fetch(String hostname) throws ScanModuleException {
        CapturedHandshake capture;
        try {
            capture = capturePermissiveHandshake(hostname);
        } catch (ScanModuleException handshakeFailure) {
            // A server that ONLY speaks weak suites (3des.badssl.com is the canonical case) rejects
            // our strong-only client outright - which used to fail the whole module with "TLS
            // handshake failed" and produce no finding for the worst TLS configuration there is.
            // The weak-cipher probe is the one thing that can still talk to such a host.
            String weakOnly = weakCipherProbe
                    .negotiatedWeakSuite(resolvedAddress(hostname), hostname, PORT)
                    .orElseThrow(() -> handshakeFailure);
            log.info("{} rejected a modern handshake but accepted {} - reporting as weak-suite-only", hostname, weakOnly);
            HstsResult hsts = fetchHstsHeader(hostname);
            return new TlsFetchResult(null, true, null, false, false, hsts.reachable(), hsts.headerValue(), null, weakOnly);
        }
        boolean chainTrusted = isChainTrusted(hostname);
        boolean tls1 = probeLegacyProtocol(hostname, "TLSv1");
        boolean tls11 = probeLegacyProtocol(hostname, "TLSv1.1");
        HstsResult hsts = fetchHstsHeader(hostname);
        String weakCipher = weakCipherProbe
                .negotiatedWeakSuite(capture.connectedAddress(), hostname, PORT)
                .orElse(null);

        return new TlsFetchResult(
                capture.notAfter(),
                chainTrusted,
                capture.cipherSuite(),
                tls1,
                tls11,
                hsts.reachable(),
                hsts.headerValue(),
                capture.issuer(),
                weakCipher);
    }

    /** The one connection that must succeed - if we can't even complete a permissive handshake, the module fails outright. */
    private CapturedHandshake capturePermissiveHandshake(String hostname) throws ScanModuleException {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {PERMISSIVE_TRUST_MANAGER}, new SecureRandom());
            try (SSLSocket socket = openSocket(ctx, hostname)) {
                socket.startHandshake();
                SSLSession session = socket.getSession();
                X509Certificate leaf = (X509Certificate) session.getPeerCertificates()[0];
                String issuer = leaf.getIssuerX500Principal().getName();
                return new CapturedHandshake(
                        leaf.getNotAfter().toInstant(),
                        session.getCipherSuite(),
                        issuer,
                        socket.getInetAddress().getHostAddress());
            }
        } catch (Exception e) {
            throw new ScanModuleException("TLS handshake failed for " + hostname + ":" + PORT, e);
        }
    }

    /**
     * Separate connection using the JDK's default trust manager (init with no
     * TrustManager array = default cacerts-backed validation). A handshake
     * failure specifically due to certificate trust means untrusted; any
     * other failure (timeout, connection reset, etc.) is a different kind of
     * problem than "we connected but didn't trust it" - treated as trusted
     * here to avoid a false TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN finding
     * off a transient network hiccup, given the permissive handshake above
     * already proved the host is reachable on 443.
     */
    private boolean isChainTrusted(String hostname) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            try (SSLSocket socket = openSocket(ctx, hostname)) {
                socket.startHandshake();
                return true;
            }
        } catch (SSLHandshakeException e) {
            return false;
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Attempts a handshake restricted to exactly one legacy protocol. Whether the JDK will even
     * offer TLSv1/TLSv1.1 is decided once, at JVM startup, by LegacyTlsProbeSupport (called from
     * WorkerApplication.main) - this method used to relax jdk.tls.disabledAlgorithms itself, per
     * probe, under a class-wide lock, and that never worked: the JDK had already frozen protocol
     * availability during the permissive handshake that precedes this, so every probe failed with
     * "No appropriate protocol" and the finding was dead. If startup config is ever missing again,
     * {@code getEnabledProtocols()} comes back empty and the guard below logs it loudly instead of
     * silently reporting "no legacy TLS" for every host.
     *
     * <p>setEnabledProtocols pins the probe to the one version asked for: the JDK's "TLSv1.1"
     * context enables TLSv1.1 <em>and</em> TLSv1, so without it a TLSv1-only server would be
     * reported as supporting TLSv1.1 as well. The negotiated version is checked for the same reason.
     */
    private boolean probeLegacyProtocol(String hostname, String protocol) {
        try {
            SSLContext ctx = SSLContext.getInstance(protocol);
            ctx.init(null, new TrustManager[] {PERMISSIVE_TRUST_MANAGER}, new SecureRandom());
            try (SSLSocket socket = openSocket(ctx, hostname)) {
                if (!Arrays.asList(socket.getEnabledProtocols()).contains(protocol)) {
                    log.warn(
                            "{} is not available in this JVM - LegacyTlsProbeSupport was not applied before TLS "
                                    + "initialised; TLS_WEAK_PROTOCOL_SUPPORTED cannot fire",
                            protocol);
                    return false;
                }
                socket.setEnabledProtocols(new String[] {protocol});
                socket.startHandshake();
                return protocol.equals(socket.getSession().getProtocol());
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static String resolvedAddress(String hostname) throws ScanModuleException {
        try {
            return SafeAddressValidator.resolveSafeAddress(hostname).getHostAddress();
        } catch (IOException e) {
            throw new ScanModuleException("could not resolve " + hostname, e);
        }
    }

    private SSLSocket openSocket(SSLContext ctx, String hostname) throws IOException {
        // Unlike every other target-facing fetcher in this codebase, this class's three SSL socket
        // probes connect by hostname string with no SafeAddressValidator check anywhere - HostFanOut's
        // one check happens before any of them, well before this method is reached. Checking here (the
        // single shared connect point for all three) closes that gap the same way ExposedPathFetcher's
        // doProbe() does for its own independent connections.
        //
        // resolveSafeAddress, not requireSafeIfResolvable + a hostname-based InetSocketAddress: a
        // security review caught that pairing them left a real DNS-rebinding TOCTOU window - the
        // validator's own resolution and the socket's independent resolution moments later could
        // disagree. Connecting directly to the one already-validated address closes it. SNI is
        // unaffected: it's set explicitly below via SNIHostName regardless of which InetSocketAddress
        // overload is used to connect, and this class never enables hostname-based certificate
        // verification in the first place (the permissive/legacy-protocol probes want whatever cert
        // is presented, and isChainTrusted only checks chain trust, not hostname match).
        InetAddress resolved = SafeAddressValidator.resolveSafeAddress(hostname);
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket();
        socket.connect(new InetSocketAddress(resolved, PORT), CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(SOCKET_TIMEOUT_MS);
        SSLParameters params = socket.getSSLParameters();
        params.setServerNames(List.of(new SNIHostName(hostname)));
        socket.setSSLParameters(params);
        return socket;
    }

    /** httpsReachable=false (rather than treating the header as simply absent) skips HSTS findings entirely - see TlsDecisionLogic. */
    private HstsResult fetchHstsHeader(String hostname) {
        try {
            SafeAddressValidator.requireSafeIfResolvable(hostname);
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://" + hostname + "/"))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", ScanUserAgent.VALUE)
                    .GET()
                    .build();
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return new HstsResult(true, response.headers().firstValue("strict-transport-security").orElse(null));
        } catch (Exception e) {
            return new HstsResult(false, null);
        }
    }

    /** connectedAddress: the SafeAddressValidator-resolved IP this handshake actually used - reused by the zgrab2 probe so it can't resolve differently. */
    private record CapturedHandshake(java.time.Instant notAfter, String cipherSuite, String issuer, String connectedAddress) {}

    private record HstsResult(boolean reachable, String headerValue) {}
}
