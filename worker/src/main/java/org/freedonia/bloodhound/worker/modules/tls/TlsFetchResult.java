package org.freedonia.bloodhound.worker.modules.tls;

import java.time.Instant;

/**
 * Raw output of the TLS fetch step - see TlsFetcher. certNotAfter/cipherSuite
 * come from a permissive-trust handshake (so expiry/cipher can be read even
 * when the chain itself doesn't validate); chainTrusted comes from a
 * separate, default-trust-store connection attempt.
 */
public record TlsFetchResult(
        Instant certNotAfter,
        boolean chainTrusted,
        String cipherSuite,
        boolean tls1Supported,
        boolean tls11Supported,
        boolean httpsReachable,
        String hstsHeaderValue,
        String certIssuer) {}
