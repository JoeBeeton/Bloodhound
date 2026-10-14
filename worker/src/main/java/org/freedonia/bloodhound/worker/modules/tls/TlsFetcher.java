package org.freedonia.bloodhound.worker.modules.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
    private final HstsPreloadClient hstsPreloadClient = new HstsPreloadClient();

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
            String preloadStatus = preloadListStatusIfClaimed(hostname, hsts.headerValue());
            return new TlsFetchResult(
                    null, true, null, false, false, hsts.reachable(), hsts.headerValue(), null, weakOnly, null, null,
                    null, null, false, null, false, preloadStatus);
        }
        boolean chainTrusted = isChainTrusted(hostname);
        boolean sslv3 = probeProtocol(hostname, "SSLv3");
        boolean tls1 = probeProtocol(hostname, "TLSv1");
        boolean tls11 = probeProtocol(hostname, "TLSv1.1");
        boolean tls13 = probeProtocol(hostname, "TLSv1.3");
        HstsResult hsts = fetchHstsHeader(hostname);
        String preloadStatus = preloadListStatusIfClaimed(hostname, hsts.headerValue());
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
                weakCipher,
                capture.dnsNames(),
                capture.sigAlgName(),
                capture.publicKeyAlgorithm(),
                capture.publicKeyBits(),
                sslv3,
                capture.protocolVersion(),
                tls13,
                preloadStatus);
    }

    /**
     * hstspreload.org's status API is only ever worth calling for the small subset of hosts whose
     * own HSTS header already claims the preload token - everyone else can't have a meaningful
     * mismatch between "what the header claims" and "what's really on browsers' preload lists".
     * Failure (network error, non-200, unparseable body) yields null - "unknown", not a finding -
     * same silence-over-guess precedent as every other best-effort signal in this codebase.
     */
    private String preloadListStatusIfClaimed(String hostname, String hstsHeaderValue) {
        if (hstsHeaderValue == null || !hstsHeaderValue.toLowerCase(java.util.Locale.ROOT).contains("preload")) {
            return null;
        }
        try {
            return hstsPreloadClient.parseStatus(hstsPreloadClient.fetchRaw(hostname));
        } catch (Exception e) {
            log.warn("hstspreload.org status lookup failed for {}: {}", hostname, e.toString());
            return null;
        }
    }

    /** Only RSA/DSA key sizes are meaningful to compare against a fixed bit-length floor - an EC key of 256 bits is not weak the way an RSA key of 256 bits would be (roughly equivalent strength to a 3072-bit RSA key), so this deliberately returns null (not evaluated) for anything else. */
    private static String publicKeyAlgorithm(PublicKey key) {
        if (key instanceof RSAPublicKey) {
            return "RSA";
        }
        if (key instanceof DSAPublicKey) {
            return "DSA";
        }
        return key.getAlgorithm();
    }

    private static Integer publicKeyBits(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (key instanceof DSAPublicKey dsa) {
            return dsa.getParams().getP().bitLength();
        }
        return null;
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
                        socket.getInetAddress().getHostAddress(),
                        dnsNames(leaf),
                        leaf.getSigAlgName(),
                        publicKeyAlgorithm(leaf.getPublicKey()),
                        publicKeyBits(leaf.getPublicKey()),
                        session.getProtocol());
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
     * Attempts a handshake restricted to exactly one protocol version - used both for legacy
     * protocols (SSLv3/TLSv1/TLSv1.1, where a true result is a finding) and for TLSv1.3 (where a
     * false result is the finding - see TLS_1_3_NOT_SUPPORTED). Whether the JDK will even offer
     * SSLv3/TLSv1/TLSv1.1 is decided once, at JVM startup, by LegacyTlsProbeSupport (called from
     * WorkerApplication.main) - this method used to relax jdk.tls.disabledAlgorithms itself, per
     * probe, under a class-wide lock, and that never worked: the JDK had already frozen protocol
     * availability during the permissive handshake that precedes this, so every probe failed with
     * "No appropriate protocol" and the finding was dead. If startup config is ever missing again,
     * {@code getEnabledProtocols()} comes back empty and the guard below logs it loudly instead of
     * silently reporting "no legacy TLS" for every host. TLSv1.3 needs no such relaxation - it was
     * never in the disabled list - so this same method works for it unmodified.
     *
     * <p>setEnabledProtocols pins the probe to the one version asked for: the JDK's "TLSv1.1"
     * context enables TLSv1.1 <em>and</em> TLSv1, so without it a TLSv1-only server would be
     * reported as supporting TLSv1.1 as well. The negotiated version is checked for the same reason.
     */
    private boolean probeProtocol(String hostname, String protocol) {
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

    /**
     * The names this certificate is valid for: SAN dNSName entries (type 2), falling back to the
     * subject CN only when there are none at all (a pre-2017 legacy shape; browsers ignore CN
     * when a SAN extension is present, and so does this check).
     */
    static List<String> dnsNames(X509Certificate leaf) {
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String name) {
                        names.add(name.toLowerCase(Locale.ROOT));
                    }
                }
            }
        } catch (CertificateParsingException ignored) {
            // unparseable SAN extension - fall through to CN
        }
        if (names.isEmpty()) {
            Matcher cn = CN_PATTERN.matcher(leaf.getSubjectX500Principal().getName());
            if (cn.find()) {
                names.add(cn.group(1).toLowerCase(Locale.ROOT));
            }
        }
        return names;
    }

    private static final Pattern CN_PATTERN = Pattern.compile("(?:^|,)CN=([^,]+)");

    /** connectedAddress: the SafeAddressValidator-resolved IP this handshake actually used - reused by the zgrab2 probe so it can't resolve differently. */
    private record CapturedHandshake(
            java.time.Instant notAfter,
            String cipherSuite,
            String issuer,
            String connectedAddress,
            List<String> dnsNames,
            String sigAlgName,
            String publicKeyAlgorithm,
            Integer publicKeyBits,
            String protocolVersion) {}

    private record HstsResult(boolean reachable, String headerValue) {}
}
