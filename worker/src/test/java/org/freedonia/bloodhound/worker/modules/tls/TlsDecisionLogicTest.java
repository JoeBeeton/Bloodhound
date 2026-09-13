package org.freedonia.bloodhound.worker.modules.tls;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class TlsDecisionLogicTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final String KNOWN_ISSUER = "CN=R11,O=Let's Encrypt,C=US";

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    private static TlsFetchResult healthy(Instant notAfter) {
        return new TlsFetchResult(
                notAfter, true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER);
    }

    @Test
    void healthyConfig_producesNoFindings() {
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW);
        assertThat(findings).isEmpty();
    }

    @Test
    void expiredCert_flaggedCritical() {
        TlsFetchResult r = healthy(NOW.minus(1, ChronoUnit.DAYS));
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_CERT_EXPIRED");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
        });
    }

    @Test
    void certExpiringWithin30Days_flaggedMedium() {
        TlsFetchResult r = healthy(NOW.plus(10, ChronoUnit.DAYS));
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_CERT_EXPIRING_SOON");
    }

    @Test
    void certExpiringBeyond30Days_notFlagged() {
        TlsFetchResult r = healthy(NOW.plus(45, ChronoUnit.DAYS));
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).doesNotContain("TLS_CERT_EXPIRING_SOON");
    }

    @Test
    void untrustedChain_flagged() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), false, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN");
    }

    /** Host in the asset, not just evidence: two hosts in one target must not dedupe into one finding. */
    @Test
    void tls1Supported_flaggedWithHostAndProtocolAsAffectedAsset() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", true, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_WEAK_PROTOCOL_SUPPORTED");
            assertThat(f.affectedAsset()).isEqualTo("example.com: TLSv1");
            assertThat(f.evidence()).containsEntry("hostname", "example.com").containsEntry("protocol", "TLSv1");
        });
    }

    @Test
    void tls11Supported_flaggedSeparatelyFromTls1() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", true, true, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        long weakProtocolFindings =
                findings.stream().filter(f -> f.ruleId().equals("TLS_WEAK_PROTOCOL_SUPPORTED")).count();
        assertThat(weakProtocolFindings).isEqualTo(2);
    }

    @Test
    void neitherLegacyProtocolSupported_notFlagged() {
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW);
        assertThat(ruleIds(findings)).doesNotContain("TLS_WEAK_PROTOCOL_SUPPORTED");
    }

    @Test
    void weakCipher_flagged() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_RSA_WITH_RC4_128_SHA", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_WEAK_CIPHER_SUITE");
    }

    @Test
    void strongCipher_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_WEAK_CIPHER_SUITE");
    }

    @Test
    void missingHsts_flagged() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true, null, KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_NO_HSTS");
    }

    @Test
    void hstsShortMaxAge_flaggedAsWeak() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=3600", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_HSTS_SHORT_MAX_AGE");
    }

    @Test
    void hstsMissingIncludeSubDomains_flaggedAsWeakEvenWithLongMaxAge() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_HSTS_SHORT_MAX_AGE");
    }

    @Test
    void httpsUnreachable_skipsHstsFindingsEntirely() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, false, null, KNOWN_ISSUER);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(ruleIds(findings)).doesNotContain("TLS_NO_HSTS", "TLS_HSTS_SHORT_MAX_AGE");
    }

    @Test
    void parseMaxAge_extractsValue() {
        assertThat(TlsDecisionLogic.parseMaxAge("max-age=15552000; includeSubDomains")).isEqualTo(15552000L);
    }

    @Test
    void parseMaxAge_missingValueDefaultsToZero() {
        assertThat(TlsDecisionLogic.parseMaxAge("includeSubDomains")).isEqualTo(0L);
    }

    @Test
    void knownIssuer_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_CT_UNEXPECTED_ISSUER");
    }

    @Test
    void unknownIssuer_flagged() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", "CN=Suspicious Issuer,O=Totally Legit CA,C=XX");
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_CT_UNEXPECTED_ISSUER");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
    }

    @Test
    void nullIssuer_doesNotThrowOrFlag() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", null);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).doesNotContain("TLS_CT_UNEXPECTED_ISSUER");
    }

    @Test
    void isKnownIssuer_caseInsensitiveSubstringMatch() {
        assertThat(TlsDecisionLogic.isKnownIssuer("CN=R11,O=Let's Encrypt,C=US")).isTrue();
        assertThat(TlsDecisionLogic.isKnownIssuer("cn=e1,o=let's encrypt,c=us")).isTrue();
        assertThat(TlsDecisionLogic.isKnownIssuer("CN=some,O=DigiCert Inc,C=US")).isTrue();
        assertThat(TlsDecisionLogic.isKnownIssuer("CN=x,O=Totally Legit CA,C=XX")).isFalse();
    }

    /** The probe result is the check that actually fires in practice - see WeakCipherProbe. */
    @Test
    void weakSuiteAcceptedByProbe_flaggedEvenThoughOurOwnHandshakeWasStrong() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, "TLS_RSA_WITH_RC4_128_SHA");
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_WEAK_CIPHER_SUITE");
            assertThat(f.evidence()).containsEntry("cipherSuite", "TLS_RSA_WITH_RC4_128_SHA");
        });
        assertThat(findings.stream().filter(f -> f.ruleId().equals("TLS_WEAK_CIPHER_SUITE")).count()).isEqualTo(1);
    }

    private static TlsFetchResult withCertNames(List<String> names) {
        return new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, names);
    }

    /** The live case: a cert for one name served on a sibling hostname. */
    @Test
    void certificateNotCoveringHostname_flaggedHigh() {
        List<RawFinding> findings = TlsDecisionLogic.decide(
                "svc-v1-0.prod.example.com", withCertNames(List.of("svc.prod.example.com")), NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_CERT_HOSTNAME_MISMATCH");
            assertThat(f.evidence()).containsEntry("certificateNames", List.of("svc.prod.example.com"));
        });
    }

    @Test
    void certificateCoveringHostnameExactlyOrByWildcard_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("www.example.com", withCertNames(List.of("example.com", "www.example.com")), NOW)))
                .doesNotContain("TLS_CERT_HOSTNAME_MISMATCH");
        assertThat(ruleIds(TlsDecisionLogic.decide("api.example.com", withCertNames(List.of("*.example.com")), NOW)))
                .doesNotContain("TLS_CERT_HOSTNAME_MISMATCH");
    }

    /** RFC 6125: a wildcard matches exactly one label, and never the bare parent. */
    @Test
    void wildcardMatchesOneLabelOnly() {
        assertThat(TlsDecisionLogic.certCovers("a.example.com", List.of("*.example.com"))).isTrue();
        assertThat(TlsDecisionLogic.certCovers("a.b.example.com", List.of("*.example.com"))).isFalse();
        assertThat(TlsDecisionLogic.certCovers("example.com", List.of("*.example.com"))).isFalse();
        assertThat(TlsDecisionLogic.certCovers("A.EXAMPLE.COM", List.of("*.example.com"))).isTrue();
    }

    /** No certificate names known (weak-suite-only path, or legacy result shape) - no verdict, no finding. */
    @Test
    void unknownCertificateNames_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", withCertNames(null), NOW)))
                .doesNotContain("TLS_CERT_HOSTNAME_MISMATCH");
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_CERT_HOSTNAME_MISMATCH");
    }
}
