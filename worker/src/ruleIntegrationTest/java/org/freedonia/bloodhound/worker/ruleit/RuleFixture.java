package org.freedonia.bloodhound.worker.ruleit;

import org.freedonia.bloodhound.worker.modules.tls.LegacyTlsProbeSupport;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.Assumptions;

/**
 * Starts HTTP :80, TLS :443, and DNS 1.1.1.1:53 once per JVM.
 * Outside the network namespace the binds fail and the tests skip.
 * Run {@code scripts/run-rule-integration-tests.sh}.
 */
public final class RuleFixture implements BeforeAllCallback {

    private static volatile boolean started;

    static {
        // Before any SSL class this extension loads. The JVM also appends rule-integration.security.
        LegacyTlsProbeSupport.enableLegacyProtocolProbing();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        ensureStarted();
    }

    public static void ensureStarted() {
        if (started) {
            return;
        }
        synchronized (RuleFixture.class) {
            if (started) {
                return;
            }
            DnsAuthority dns = null;
            LoopbackHttpServer http = null;
            TlsServer tls = null;
            try {
                dns = DnsAuthority.start();
                http = LoopbackHttpServer.start(80, HttpResponses::route);
                tls = TlsServer.start(HttpResponses::route);
                started = true;
                // Kept alive for the JVM. Daemon threads die with the test process.
                DnsAuthority keepDns = dns;
                LoopbackHttpServer keepHttp = http;
                TlsServer keepTls = tls;
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    keepTls.close();
                    keepHttp.close();
                    keepDns.close();
                }));
            } catch (Exception e) {
                if (tls != null) {
                    tls.close();
                }
                if (http != null) {
                    http.close();
                }
                if (dns != null) {
                    dns.close();
                }
                if ("1".equals(System.getenv("BH_RULE_IT_NS"))) {
                    throw new IllegalStateException("rule fixture failed inside the network namespace", e);
                }
                Assumptions.assumeTrue(false, "rule fixture needs scripts/run-rule-integration-tests.sh: " + e.getMessage());
            }
        }
    }
}
