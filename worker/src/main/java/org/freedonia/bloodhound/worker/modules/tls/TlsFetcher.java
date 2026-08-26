package org.freedonia.bloodhound.worker.modules.tls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

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
 * </ol>
 *
 * <p>Plus a plain HTTPS GET to read the Strict-Transport-Security header.
 */
public class TlsFetcher {

    private static final int PORT = 443;
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final String DISABLED_ALGORITHMS_PROPERTY = "jdk.tls.disabledAlgorithms";

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
        CapturedHandshake capture = capturePermissiveHandshake(hostname);
        boolean chainTrusted = isChainTrusted(hostname);
        boolean tls1 = probeLegacyProtocol(hostname, "TLSv1");
        boolean tls11 = probeLegacyProtocol(hostname, "TLSv1.1");
        HstsResult hsts = fetchHstsHeader(hostname);

        return new TlsFetchResult(
                capture.notAfter(),
                chainTrusted,
                capture.cipherSuite(),
                tls1,
                tls11,
                hsts.reachable(),
                hsts.headerValue(),
                capture.issuer());
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
                return new CapturedHandshake(leaf.getNotAfter().toInstant(), session.getCipherSuite(), issuer);
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
     * Attempts a handshake restricted to exactly one legacy protocol. Modern
     * JDKs disable TLSv1/TLSv1.1 client-side by default via the
     * jdk.tls.disabledAlgorithms security property - without relaxing it
     * here, every server would appear to reject these protocols regardless
     * of what it actually supports. Relaxed only for the duration of this
     * probe and restored in the finally block.
     *
     * <p>This mutates a JVM-wide Security property. TlsAnalysisModule now
     * fans this fetcher out across a target's root hostname and its
     * subdomains <em>concurrently</em> (see HostFanOut), so two threads
     * probing two different hosts at once could otherwise race on this same
     * global property - one thread's "restore" could clobber another's
     * "relax" mid-handshake, corrupting both probes' results. Synchronized
     * on the JVM-wide property itself (via this class's monitor) to keep the
     * relax-probe-restore sequence atomic across all concurrently-fanned-out
     * hosts; a different approach (e.g. an isolated process) would be needed
     * if this ever needed to scale beyond one JVM's worth of concurrency.
     */
    private boolean probeLegacyProtocol(String hostname, String protocol) {
        synchronized (TlsFetcher.class) {
            String original = Security.getProperty(DISABLED_ALGORITHMS_PROPERTY);
            try {
                String relaxed = original == null ? "" : original.replaceAll("(?i)TLSv1(\\.1)?,?\\s*", "");
                Security.setProperty(DISABLED_ALGORITHMS_PROPERTY, relaxed);

                SSLContext ctx = SSLContext.getInstance(protocol);
                ctx.init(null, new TrustManager[] {PERMISSIVE_TRUST_MANAGER}, new SecureRandom());
                try (SSLSocket socket = openSocket(ctx, hostname)) {
                    socket.startHandshake();
                    return true;
                }
            } catch (Exception e) {
                return false;
            } finally {
                Security.setProperty(DISABLED_ALGORITHMS_PROPERTY, original == null ? "" : original);
            }
        }
    }

    private SSLSocket openSocket(SSLContext ctx, String hostname) throws IOException {
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket();
        socket.connect(new InetSocketAddress(hostname, PORT), CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(SOCKET_TIMEOUT_MS);
        SSLParameters params = socket.getSSLParameters();
        params.setServerNames(List.of(new SNIHostName(hostname)));
        socket.setSSLParameters(params);
        return socket;
    }

    /** httpsReachable=false (rather than treating the header as simply absent) skips HSTS findings entirely - see TlsDecisionLogic. */
    private HstsResult fetchHstsHeader(String hostname) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://" + hostname + "/"))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "Bloodhound-ASM/1.0 (+passive surface scan)")
                    .GET()
                    .build();
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return new HstsResult(true, response.headers().firstValue("strict-transport-security").orElse(null));
        } catch (Exception e) {
            return new HstsResult(false, null);
        }
    }

    private record CapturedHandshake(java.time.Instant notAfter, String cipherSuite, String issuer) {}

    private record HstsResult(boolean reachable, String headerValue) {}
}
