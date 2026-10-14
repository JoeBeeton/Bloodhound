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

    /** Genuinely clean under every rule in this class, including the newer protocol/PFS/preload-list ones - the fixture behind the one true isEmpty() assertion. */
    private static TlsFetchResult healthy(Instant notAfter) {
        return new TlsFetchResult(
                notAfter, true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, null, null, null, false,
                "TLSv1.3", true, null);
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

    /** SSLv3 shares the same TLS_WEAK_PROTOCOL_SUPPORTED rule and "<host>: <protocol>" asset convention as TLSv1/TLSv1.1. */
    @Test
    void sslv3Supported_flaggedUnderTheSameLegacyProtocolRule() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, null, null, null, true, "SSLv3",
                false, null);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_WEAK_PROTOCOL_SUPPORTED");
            assertThat(f.affectedAsset()).isEqualTo("example.com: SSLv3");
        });
    }

    /** SSLv3's own CBC-mode design flaw is POODLE itself - no separate probe needed, just a distinct, explicitly-named finding alongside the generic legacy-protocol one. */
    @Test
    void sslv3Supported_alsoFlaggedAsPoodleVulnerable() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, null, null, null, true, "SSLv3",
                false, null);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(ruleIds(findings)).contains("TLS_WEAK_PROTOCOL_SUPPORTED", "TLS_POODLE_VULNERABLE");
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_POODLE_VULNERABLE");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
            assertThat(f.affectedAsset()).isEqualTo("example.com");
        });
    }

    @Test
    void sslv3NotSupported_notFlaggedAsPoodleVulnerable() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_POODLE_VULNERABLE");
    }

    @Test
    void tls13NotSupported_flaggedLow() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, null, null, null, false,
                "TLSv1.2", false, null);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_1_3_NOT_SUPPORTED");
            assertThat(f.severity().name()).isEqualTo("LOW");
        });
    }

    @Test
    void tls13Supported_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_1_3_NOT_SUPPORTED");
    }

    /** RSA key exchange (no ECDHE/DHE) at TLS1.2 - the server's own choice from a client offering both. */
    @Test
    void nonPfsCipherAtTls12_flaggedNoForwardSecrecy() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_RSA_WITH_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, null, null, null, false,
                "TLSv1.2", false, null);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_NO_FORWARD_SECRECY");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
            assertThat(f.evidence()).containsEntry("cipherSuite", "TLS_RSA_WITH_AES_128_GCM_SHA256");
        });
    }

    @Test
    void ecdheCipherAtTls12_notFlaggedNoForwardSecrecy() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, null, null, null, false,
                "TLSv1.2", false, null);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).doesNotContain("TLS_NO_FORWARD_SECRECY");
    }

    /** TLS1.3 cipher suite names never encode key exchange (every 1.3 suite is inherently forward-secret) - must not be judged by name alone. */
    @Test
    void tls13CipherNameWithNoKexMarker_notFlaggedNoForwardSecrecy() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_NO_FORWARD_SECRECY");
    }

    @Test
    void nullCipherSuite_notFlaggedNoForwardSecrecy() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, null, false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, "TLS_RSA_WITH_RC4_128_SHA", null, null, null,
                null, false, null, false, null);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).doesNotContain("TLS_NO_FORWARD_SECRECY");
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

    /** The gap zone: clears the 6-month bar (no TLS_HSTS_SHORT_MAX_AGE) but not preload's 1-year one. */
    @Test
    void hstsPreloadTokenWithSubYearMaxAge_flaggedPreloadNotEligible() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=15552000; includeSubDomains; preload", KNOWN_ISSUER);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(ruleIds(findings)).contains("TLS_HSTS_PRELOAD_NOT_ELIGIBLE").doesNotContain("TLS_HSTS_SHORT_MAX_AGE");
    }

    @Test
    void hstsPreloadTokenWithoutIncludeSubDomains_flaggedPreloadNotEligibleEvenWithLongMaxAge() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=63072000; preload", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).contains("TLS_HSTS_PRELOAD_NOT_ELIGIBLE");
    }

    /** The real, live-verified github.com shape: exactly at the eligibility bar - correctly silent. */
    @Test
    void hstsPreloadTokenMeetingEligibilityBar_notFlagged() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubdomains; preload", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).doesNotContain("TLS_HSTS_PRELOAD_NOT_ELIGIBLE");
    }

    /** No preload token at all - never judged against the stricter bar, regardless of policy strength. */
    @Test
    void hstsWithoutPreloadToken_neverFlaggedPreloadNotEligible() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_HSTS_PRELOAD_NOT_ELIGIBLE");
        TlsFetchResult weak = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=3600", KNOWN_ISSUER);
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", weak, NOW))).doesNotContain("TLS_HSTS_PRELOAD_NOT_ELIGIBLE");
    }

    /** Orthogonal to eligibility: the header's own values can clear the bar while the real list still says otherwise. */
    @Test
    void hstsPreloadTokenButRealListStatusUnknown_flaggedNotOnPreloadList() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains; preload", KNOWN_ISSUER, null, null, null, null, null, false,
                "TLSv1.3", true, "unknown");
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_HSTS_NOT_ON_PRELOAD_LIST");
            assertThat(f.evidence()).containsEntry("preloadListStatus", "unknown");
        });
        // Eligible by the header's own values - this is specifically the real-list-status gap, not an eligibility gap.
        assertThat(ruleIds(findings)).doesNotContain("TLS_HSTS_PRELOAD_NOT_ELIGIBLE");
    }

    @Test
    void hstsPreloadTokenAndActuallyPreloaded_notFlagged() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains; preload", KNOWN_ISSUER, null, null, null, null, null, false,
                "TLSv1.3", true, "preloaded");
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", r, NOW))).doesNotContain("TLS_HSTS_NOT_ON_PRELOAD_LIST");
    }

    /** preloadListStatus is null whenever the lookup wasn't attempted/failed - silence, not a false "not on list" finding. */
    @Test
    void hstsPreloadTokenButStatusLookupUnavailable_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_HSTS_NOT_ON_PRELOAD_LIST");
    }

    @Test
    void httpsUnreachable_skipsHstsFindingsEntirely() {
        TlsFetchResult r = new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, false, null, KNOWN_ISSUER);
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", r, NOW);
        assertThat(ruleIds(findings))
                .doesNotContain(
                        "TLS_NO_HSTS", "TLS_HSTS_SHORT_MAX_AGE", "TLS_HSTS_PRELOAD_NOT_ELIGIBLE",
                        "TLS_HSTS_NOT_ON_PRELOAD_LIST");
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

    private static TlsFetchResult withSignatureAndKey(String sigAlg, String keyAlg, Integer keyBits) {
        return new TlsFetchResult(
                NOW.plus(200, ChronoUnit.DAYS), true, "TLS_AES_128_GCM_SHA256", false, false, true,
                "max-age=31536000; includeSubDomains", KNOWN_ISSUER, null, null, sigAlg, keyAlg, keyBits);
    }

    @Test
    void sha1SignedCertificate_flaggedHigh() {
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", withSignatureAndKey("SHA1withRSA", "RSA", 2048), NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_CERT_SIGNATURE_ALGORITHM_WEAK");
            assertThat(f.severity().name()).isEqualTo("HIGH");
            assertThat(f.evidence()).containsEntry("signatureAlgorithm", "SHA1withRSA");
        });
    }

    @Test
    void md5SignedCertificate_flaggedHigh() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", withSignatureAndKey("MD5withRSA", "RSA", 2048), NOW)))
                .contains("TLS_CERT_SIGNATURE_ALGORITHM_WEAK");
    }

    @Test
    void sha256SignedCertificate_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", withSignatureAndKey("SHA256withRSA", "RSA", 2048), NOW)))
                .doesNotContain("TLS_CERT_SIGNATURE_ALGORITHM_WEAK");
    }

    @Test
    void unknownSignatureAlgorithm_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_CERT_SIGNATURE_ALGORITHM_WEAK");
    }

    @Test
    void rsa1024BitKey_flaggedHigh() {
        List<RawFinding> findings = TlsDecisionLogic.decide("example.com", withSignatureAndKey("SHA256withRSA", "RSA", 1024), NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("TLS_CERT_KEY_TOO_SHORT");
            assertThat(f.severity().name()).isEqualTo("HIGH");
            assertThat(f.evidence()).containsEntry("publicKeyBits", 1024);
        });
    }

    @Test
    void rsa2048BitKey_notFlagged() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", withSignatureAndKey("SHA256withRSA", "RSA", 2048), NOW)))
                .doesNotContain("TLS_CERT_KEY_TOO_SHORT");
    }

    /** A 256-bit EC key is roughly as strong as a 3072-bit RSA key - the fixed bit-length floor only applies to RSA/DSA. */
    @Test
    void ecKeySmallBitLength_notFlaggedAsTooShort() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", withSignatureAndKey("SHA256withECDSA", "EC", 256), NOW)))
                .doesNotContain("TLS_CERT_KEY_TOO_SHORT");
    }

    @Test
    void unknownKeyInfo_notFlaggedAsTooShort() {
        assertThat(ruleIds(TlsDecisionLogic.decide("example.com", healthy(NOW.plus(200, ChronoUnit.DAYS)), NOW)))
                .doesNotContain("TLS_CERT_KEY_TOO_SHORT");
    }
}
