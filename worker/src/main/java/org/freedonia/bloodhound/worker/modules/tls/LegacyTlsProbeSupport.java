package org.freedonia.bloodhound.worker.modules.tls;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * JVM-startup configuration that makes TlsFetcher's TLSv1/TLSv1.1 probes possible at all.
 *
 * <p>Modern JDKs list TLSv1 and TLSv1.1 in the {@code jdk.tls.disabledAlgorithms} security
 * property. TlsFetcher used to relax that property around each probe at scan time, but the JDK
 * reads it exactly once: {@code sun.security.ssl.ProtocolVersion} computes each version's
 * {@code isAvailable} flag in its enum constructor, so by the time the first handshake of the
 * process has run (the permissive handshake that precedes every probe), the answer is frozen.
 * The runtime relax was a no-op - every {@code SSLContext.getInstance("TLSv1")} came back with an
 * empty enabled-protocol list and every probe failed with "No appropriate protocol", so
 * TLS_WEAK_PROTOCOL_SUPPORTED had never fired once in this deployment's history despite nuclei
 * flagging deprecated TLS on the same hosts. Reproduced in-container; the only working fix is to
 * set the property before any TLS class initializes, i.e. from main().
 *
 * <p>Removing the two versions from the disabled list would, on its own, also make every
 * default-context client in this worker (HttpClient to crt.sh, HIBP, the target's own HTTPS
 * endpoints, ...) offer TLSv1/TLSv1.1 in its ClientHello. That's not a downgrade vulnerability
 * against a TLS 1.2+ server (the Finished MAC covers the offered versions), but there's no reason
 * to widen it either: {@code jdk.tls.client.protocols} pins the <em>default</em> client protocol
 * list to 1.3/1.2 and, per the JDK's SSLContextImpl, is consulted only by the "TLS"/"Default"
 * contexts - the version-specific {@code SSLContext.getInstance("TLSv1")} contexts TlsFetcher
 * uses ignore it, which is exactly the split wanted here. Both verified empirically against the
 * worker image's JDK before relying on them.
 */
public final class LegacyTlsProbeSupport {

    static final String DISABLED_ALGORITHMS_PROPERTY = "jdk.tls.disabledAlgorithms";
    static final String CLIENT_PROTOCOLS_PROPERTY = "jdk.tls.client.protocols";
    private static final Set<String> LEGACY_PROTOCOLS = Set.of("TLSv1", "TLSv1.1");

    private LegacyTlsProbeSupport() {}

    /** Must run before anything in the JVM touches javax.net.ssl - call it first thing in main(). */
    public static void enableLegacyProtocolProbing() {
        Security.setProperty(
                DISABLED_ALGORITHMS_PROPERTY, withoutLegacyProtocols(Security.getProperty(DISABLED_ALGORITHMS_PROPERTY)));
        if (System.getProperty(CLIENT_PROTOCOLS_PROPERTY) == null) {
            System.setProperty(CLIENT_PROTOCOLS_PROPERTY, "TLSv1.3,TLSv1.2");
        }
    }

    /**
     * Exact-entry removal, not a substring regex: the default list also contains "DTLSv1.0", which a
     * naive {@code TLSv1} pattern (as the old scan-time relax used) chews into "D.0".
     */
    static String withoutLegacyProtocols(String disabledAlgorithms) {
        if (disabledAlgorithms == null || disabledAlgorithms.isBlank()) {
            return "";
        }
        List<String> kept = new ArrayList<>();
        for (String entry : disabledAlgorithms.split(",")) {
            String trimmed = entry.strip();
            if (!trimmed.isEmpty() && !LEGACY_PROTOCOLS.contains(trimmed)) {
                kept.add(trimmed);
            }
        }
        return String.join(", ", kept);
    }
}
