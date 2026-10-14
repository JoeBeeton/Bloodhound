package org.freedonia.bloodhound.worker.modules.tls;

import java.time.Instant;
import java.util.List;

/**
 * Raw output of the TLS fetch step - see TlsFetcher. certNotAfter/cipherSuite
 * come from a permissive-trust handshake (so expiry/cipher can be read even
 * when the chain itself doesn't validate); chainTrusted comes from a
 * separate, default-trust-store connection attempt. certDnsNames: the leaf's
 * SAN dNSName entries (plus the CN as a fallback for legacy certs), null when
 * no certificate could be read - the input to the hostname-mismatch check.
 */
public record TlsFetchResult(
        Instant certNotAfter,
        boolean chainTrusted,
        String cipherSuite,
        boolean tls1Supported,
        boolean tls11Supported,
        boolean httpsReachable,
        String hstsHeaderValue,
        String certIssuer,
        String weakCipherNegotiated,
        List<String> certDnsNames,
        String certSignatureAlgorithm,
        String certPublicKeyAlgorithm,
        Integer certPublicKeyBits,
        boolean sslv3Supported,
        String negotiatedProtocol,
        boolean tls13Supported,
        String hstsPreloadListStatus) {

    /**
     * sslv3Supported/tls13Supported: dedicated per-protocol probes, same shape as tls1Supported/
     * tls11Supported. negotiatedProtocol: the permissive handshake's own negotiated version - null
     * whenever the handshake itself failed (the weak-suite-only path). hstsPreloadListStatus: only
     * populated when the HSTS header actually carries the preload token (see TlsFetcher) - the real
     * hstspreload.org list status ("preloaded"/"pending"/"unknown"/...), not just whether the header's
     * own values clear the submission bar (that's the separate, pre-existing TLS_HSTS_PRELOAD_NOT_ELIGIBLE).
     */
    public TlsFetchResult(
            Instant certNotAfter,
            boolean chainTrusted,
            String cipherSuite,
            boolean tls1Supported,
            boolean tls11Supported,
            boolean httpsReachable,
            String hstsHeaderValue,
            String certIssuer,
            String weakCipherNegotiated,
            List<String> certDnsNames,
            String certSignatureAlgorithm,
            String certPublicKeyAlgorithm,
            Integer certPublicKeyBits) {
        this(certNotAfter, chainTrusted, cipherSuite, tls1Supported, tls11Supported, httpsReachable, hstsHeaderValue,
                certIssuer, weakCipherNegotiated, certDnsNames, certSignatureAlgorithm, certPublicKeyAlgorithm,
                certPublicKeyBits, false, null, false, null);
    }

    /** weakCipherNegotiated: the suite the server accepted when offered only known-weak ones (see WeakCipherProbe), or null. */
    public TlsFetchResult(
            Instant certNotAfter,
            boolean chainTrusted,
            String cipherSuite,
            boolean tls1Supported,
            boolean tls11Supported,
            boolean httpsReachable,
            String hstsHeaderValue,
            String certIssuer) {
        this(certNotAfter, chainTrusted, cipherSuite, tls1Supported, tls11Supported, httpsReachable, hstsHeaderValue,
                certIssuer, null, null, null, null, null);
    }

    public TlsFetchResult(
            Instant certNotAfter,
            boolean chainTrusted,
            String cipherSuite,
            boolean tls1Supported,
            boolean tls11Supported,
            boolean httpsReachable,
            String hstsHeaderValue,
            String certIssuer,
            String weakCipherNegotiated) {
        this(certNotAfter, chainTrusted, cipherSuite, tls1Supported, tls11Supported, httpsReachable, hstsHeaderValue,
                certIssuer, weakCipherNegotiated, null, null, null, null);
    }

    public TlsFetchResult(
            Instant certNotAfter,
            boolean chainTrusted,
            String cipherSuite,
            boolean tls1Supported,
            boolean tls11Supported,
            boolean httpsReachable,
            String hstsHeaderValue,
            String certIssuer,
            String weakCipherNegotiated,
            List<String> certDnsNames) {
        this(certNotAfter, chainTrusted, cipherSuite, tls1Supported, tls11Supported, httpsReachable, hstsHeaderValue,
                certIssuer, weakCipherNegotiated, certDnsNames, null, null, null);
    }
}
