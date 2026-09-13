package org.freedonia.bloodhound.worker.modules.tls;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.worker.modules.portscan.Zgrab2Fetcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asks a server whether it will negotiate a known-weak cipher suite, by offering only weak
 * suites (via zgrab2 - see {@link Zgrab2Fetcher#tlsJson}).
 *
 * <p>TLS_WEAK_CIPHER_SUITE used to be judged from the suite negotiated in TlsFetcher's normal
 * handshake. A rules audit found that could never fire: a modern JDK client doesn't offer RC4,
 * DES, 3DES, NULL, EXPORT or anonymous suites at all (jdk.tls.disabledAlgorithms), so the
 * negotiated suite is always one of the client's strong ones - the server's willingness to
 * speak a weak one is invisible from that handshake. The rule had zero findings in this
 * deployment's history while nuclei's weak-cipher-suites template was flagging the same hosts.
 * zgrab2's TLS stack (zcrypto) still implements the weak suites, so offering only those and
 * seeing what the server picks is a direct, positive test - verified against 3des.badssl.com
 * (negotiates TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA) and rc4.badssl.com (TLS_RSA_WITH_RC4_128_SHA),
 * with google.com and a hardened bank subdomain correctly refusing the handshake.
 */
public class WeakCipherProbe {

    private static final Logger log = LoggerFactory.getLogger(WeakCipherProbe.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * IANA cipher suite codes for RC4, single/triple DES, EXPORT-grade, NULL-encryption and
     * anonymous-DH suites - every one either broken (RC4, DES, EXPORT, NULL) or deprecated for
     * a practical attack (3DES: Sweet32) or offering no authentication at all (DH_anon).
     */
    static final List<String> WEAK_SUITES = List.of(
            "0x0004", // TLS_RSA_WITH_RC4_128_MD5
            "0x0005", // TLS_RSA_WITH_RC4_128_SHA
            "0xc011", // TLS_ECDHE_RSA_WITH_RC4_128_SHA
            "0xc007", // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
            "0x000a", // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            "0xc012", // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            "0xc008", // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
            "0x0016", // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
            "0x0009", // TLS_RSA_WITH_DES_CBC_SHA
            "0x0015", // TLS_DHE_RSA_WITH_DES_CBC_SHA
            "0x0003", // TLS_RSA_EXPORT_WITH_RC4_40_MD5
            "0x0006", // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            "0x0008", // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            "0x0014", // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            "0x0001", // TLS_RSA_WITH_NULL_MD5
            "0x0002", // TLS_RSA_WITH_NULL_SHA
            "0x003b", // TLS_RSA_WITH_NULL_SHA256
            "0x0018", // TLS_DH_anon_WITH_RC4_128_MD5
            "0x001b", // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
            "0x0034", // TLS_DH_anon_WITH_AES_128_CBC_SHA
            "0x003a"); // TLS_DH_anon_WITH_AES_256_CBC_SHA

    private final Zgrab2Fetcher zgrab2;

    public WeakCipherProbe() {
        this(new Zgrab2Fetcher());
    }

    WeakCipherProbe(Zgrab2Fetcher zgrab2) {
        this.zgrab2 = zgrab2;
    }

    /**
     * The weak suite the server chose, or empty if it refused every one offered (the correct,
     * expected outcome) - or if the probe itself couldn't run, which is logged rather than
     * reported: "unknown" must not become a finding, same principle as FallbackDnsLookup.
     */
    public Optional<String> negotiatedWeakSuite(String ip, String hostname, int port) {
        try {
            return parse(zgrab2.tlsJson(ip, hostname, port, WEAK_SUITES));
        } catch (ScanModuleException e) {
            log.warn("weak-cipher probe could not run for {}: {}", hostname, e.getMessage());
            return Optional.empty();
        }
    }

    /** Pure: zgrab2's JSON for one target to the negotiated suite name, if the handshake succeeded. */
    static Optional<String> parse(String zgrab2Json) {
        try {
            JsonNode tls = MAPPER.readTree(zgrab2Json).path("data").path("tls");
            if (!"success".equals(tls.path("status").asText())) {
                return Optional.empty();
            }
            JsonNode suite = tls.path("result").path("handshake_log").path("server_hello").path("cipher_suite");
            String name = suite.path("name").asText(null);
            if (name == null || name.isBlank()) {
                name = suite.path("hex").asText(null);
            }
            return Optional.ofNullable(name);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
