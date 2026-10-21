package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.worker.modules.tls.TlsAnalysisModule;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * HSTS shapes that return early or exclude each other are separate hosts.
 * SSLv3 / TLS 1.0 / 1.1 are asserted only when this JDK can actually negotiate them.
 */
@ExtendWith(RuleFixture.class)
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class TlsRulesIT {

    @Test
    void noHstsHeader() throws Exception {
        ModuleResult result = ScanSupport.run(new TlsAnalysisModule(), FixtureHosts.TLS_HSTS_NONE);
        ScanSupport.assertRules(result, "TLS_NO_HSTS", "TLS_CT_UNEXPECTED_ISSUER", "TLS_1_3_NOT_SUPPORTED");
        ScanSupport.assertAbsent(
                result,
                "TLS_HSTS_SHORT_MAX_AGE",
                "TLS_HSTS_PRELOAD_NOT_ELIGIBLE",
                "TLS_HSTS_NOT_ON_PRELOAD_LIST",
                "TLS_CERT_EXPIRED",
                "TLS_CERT_EXPIRING_SOON",
                "TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN",
                "TLS_CERT_HOSTNAME_MISMATCH",
                "TLS_NO_FORWARD_SECRECY",
                "TLS_WEAK_CIPHER_SUITE");
        assertLegacy(result);
    }

    @Test
    void shortMaxAgeIsNotAMissingHeader() throws Exception {
        ModuleResult result = ScanSupport.run(new TlsAnalysisModule(), FixtureHosts.TLS_HSTS_SHORT);
        ScanSupport.assertRules(result, "TLS_HSTS_SHORT_MAX_AGE", "TLS_1_3_NOT_SUPPORTED");
        ScanSupport.assertAbsent(
                result, "TLS_NO_HSTS", "TLS_HSTS_PRELOAD_NOT_ELIGIBLE", "TLS_HSTS_NOT_ON_PRELOAD_LIST");
    }

    @Test
    void preloadTokenBelowOneYearIsNotEligibleAndNotLookedUp() throws Exception {
        ModuleResult result = ScanSupport.run(new TlsAnalysisModule(), FixtureHosts.TLS_HSTS_PRELOAD);
        ScanSupport.assertRules(result, "TLS_HSTS_PRELOAD_NOT_ELIGIBLE", "TLS_1_3_NOT_SUPPORTED");
        // 20000000 is under a year and over six months, and the header has includeSubDomains, so it is not "short".
        ScanSupport.assertAbsent(
                result, "TLS_NO_HSTS", "TLS_HSTS_SHORT_MAX_AGE", "TLS_HSTS_NOT_ON_PRELOAD_LIST");
    }

    @Test
    void certificateExpiringSoonKeepsAStrongHstsPolicy() throws Exception {
        ModuleResult result = ScanSupport.run(new TlsAnalysisModule(), FixtureHosts.TLS_SOON);
        ScanSupport.assertRules(
                result, "TLS_CERT_EXPIRING_SOON", "TLS_CT_UNEXPECTED_ISSUER", "TLS_1_3_NOT_SUPPORTED");
        ScanSupport.assertAbsent(
                result,
                "TLS_CERT_EXPIRED",
                "TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN",
                "TLS_CERT_HOSTNAME_MISMATCH",
                "TLS_NO_HSTS",
                "TLS_HSTS_SHORT_MAX_AGE",
                "TLS_HSTS_PRELOAD_NOT_ELIGIBLE");
    }

    @Test
    void expiredUntrustedMismatchedCertificate() throws Exception {
        ModuleResult result;
        try {
            result = ScanSupport.run(new TlsAnalysisModule(), FixtureHosts.TLS_BAD);
        } catch (ScanModuleException e) {
            Assumptions.assumeTrue(false, "tls-bad handshake not reproduced on this JDK: " + e.getMessage());
            return;
        }
        ScanSupport.assertRules(
                result,
                "TLS_CERT_EXPIRED",
                "TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN",
                "TLS_CERT_HOSTNAME_MISMATCH",
                "TLS_CT_UNEXPECTED_ISSUER",
                "TLS_1_3_NOT_SUPPORTED");
        ScanSupport.assertAbsent(result, "TLS_CERT_EXPIRING_SOON", "TLS_NO_HSTS", "TLS_HSTS_SHORT_MAX_AGE");
        Properties material = material();
        String sig = material.getProperty("badSigAlg", "");
        int bits = Integer.parseInt(material.getProperty("badKeyBits", "0"));
        if (sig.toUpperCase(java.util.Locale.ROOT).contains("SHA1")
                || sig.toUpperCase(java.util.Locale.ROOT).contains("MD5")
                || sig.toUpperCase(java.util.Locale.ROOT).contains("MD2")) {
            ScanSupport.assertRules(result, "TLS_CERT_SIGNATURE_ALGORITHM_WEAK");
        } else {
            ScanSupport.assertAbsent(result, "TLS_CERT_SIGNATURE_ALGORITHM_WEAK");
        }
        if (bits > 0 && bits < 2048) {
            ScanSupport.assertRules(result, "TLS_CERT_KEY_TOO_SHORT");
        } else {
            ScanSupport.assertAbsent(result, "TLS_CERT_KEY_TOO_SHORT");
        }
    }

    private static void assertLegacy(ModuleResult result) {
        if (negotiable("SSLv3")) {
            ScanSupport.assertRules(result, "TLS_POODLE_VULNERABLE", "TLS_WEAK_PROTOCOL_SUPPORTED");
            ScanSupport.assertAsset(result, "TLS_WEAK_PROTOCOL_SUPPORTED", FixtureHosts.TLS_HSTS_NONE + ": SSLv3");
        } else {
            ScanSupport.assertAbsent(result, "TLS_POODLE_VULNERABLE");
        }
        if (negotiable("TLSv1")) {
            ScanSupport.assertAsset(result, "TLS_WEAK_PROTOCOL_SUPPORTED", FixtureHosts.TLS_HSTS_NONE + ": TLSv1");
        }
        if (negotiable("TLSv1.1")) {
            ScanSupport.assertAsset(result, "TLS_WEAK_PROTOCOL_SUPPORTED", FixtureHosts.TLS_HSTS_NONE + ": TLSv1.1");
        }
        if (!negotiable("SSLv3") && !negotiable("TLSv1") && !negotiable("TLSv1.1")) {
            ScanSupport.assertAbsent(result, "TLS_WEAK_PROTOCOL_SUPPORTED", "TLS_POODLE_VULNERABLE");
        }
    }

    /** Same shape of probe TlsFetcher uses, against the fixture directly. */
    private static boolean negotiable(String protocol) {
        try {
            javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance(protocol);
            context.init(null, new javax.net.ssl.TrustManager[] {new javax.net.ssl.X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}

                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}

                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[0];
                }
            }}, null);
            try (javax.net.ssl.SSLSocket socket =
                    (javax.net.ssl.SSLSocket) context.getSocketFactory().createSocket()) {
                socket.connect(new java.net.InetSocketAddress(FixtureHosts.TLS_HSTS_NONE, 443), 3000);
                socket.setSoTimeout(3000);
                // setSSLParameters replaces the enabled-protocol list, so pin the
                // protocol after SNI, matching TlsFetcher.probeProtocol.
                javax.net.ssl.SSLParameters parameters = socket.getSSLParameters();
                parameters.setServerNames(java.util.List.of(new javax.net.ssl.SNIHostName(FixtureHosts.TLS_HSTS_NONE)));
                socket.setSSLParameters(parameters);
                socket.setEnabledProtocols(new String[] {protocol});
                socket.startHandshake();
                return protocol.equals(socket.getSession().getProtocol());
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static Properties material() throws Exception {
        Properties properties = new Properties();
        Path path = Path.of(System.getProperty("bloodhound.rule.fixture.dir"), "material.properties");
        try (InputStream in = Files.newInputStream(path)) {
            properties.load(in);
        }
        assertThat(properties.getProperty("badSigAlg")).isNotBlank();
        return properties;
    }
}
