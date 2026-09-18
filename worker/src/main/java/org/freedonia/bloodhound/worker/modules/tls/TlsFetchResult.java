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
        Integer certPublicKeyBits) {

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
