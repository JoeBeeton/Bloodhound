package org.freedonia.bloodhound.worker.modules.tls;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class WeakCipherProbeTest {

    /** Trimmed from a real zgrab2 run against 3des.badssl.com. */
    private static final String ACCEPTED = "{\"ip\":\"104.154.89.105\",\"domain\":\"3des.badssl.com\",\"data\":{\"tls\":"
            + "{\"status\":\"success\",\"protocol\":\"tls\",\"port\":443,\"result\":{\"handshake_log\":{\"server_hello\":"
            + "{\"version\":{\"name\":\"TLSv1.2\",\"value\":771},\"cipher_suite\":{\"hex\":\"0xc012\","
            + "\"name\":\"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA\",\"value\":49170}}}}}}}";

    /** Trimmed from a real zgrab2 run against a hardened host - the expected, correct outcome. */
    private static final String REFUSED = "{\"ip\":\"91.235.132.77\",\"domain\":\"check.example.finance\",\"data\":{\"tls\":"
            + "{\"status\":\"unknown-error\",\"protocol\":\"tls\",\"port\":443,\"error\":\"could not successfully "
            + "complete tls handshake for target check.example.finance(91.235.132.77): remote error: tls: handshake failure\"}}}";

    @Test
    void serverAcceptingAWeakSuite_isReportedByName() {
        assertThat(WeakCipherProbe.parse(ACCEPTED)).contains("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
    }

    @Test
    void handshakeFailure_meansNoWeakSuite() {
        assertThat(WeakCipherProbe.parse(REFUSED)).isEmpty();
    }

    @Test
    void garbageOutput_isNotAFinding() {
        assertThat(WeakCipherProbe.parse("")).isEmpty();
        assertThat(WeakCipherProbe.parse("not json")).isEmpty();
        assertThat(WeakCipherProbe.parse("{\"data\":{}}")).isEmpty();
    }

    @Test
    void everyOfferedSuiteIsAnIanaHexCode() {
        assertThat(WeakCipherProbe.WEAK_SUITES).allMatch(s -> s.matches("0x[0-9a-f]{4}")).hasSizeGreaterThan(15);
    }
}
