package org.freedonia.bloodhound.server.tls;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.server.findings.FindingRepository.TlsFindingRow;
import org.junit.jupiter.api.Test;

class TlsGradeCalculatorTest {

    @Test
    void noFindings_notScanned() {
        TlsGradeCalculator.Result result = TlsGradeCalculator.calculate(List.of());
        assertThat(result.grade()).isNull();
        assertThat(result.factors()).isEmpty();
    }

    @Test
    void nullFindingsList_notScanned() {
        assertThat(TlsGradeCalculator.calculate(null).grade()).isNull();
    }

    @Test
    void cleanHostWithNoFindingsAtAll_notFlaggedAsAPlus_itsSimplyUnscanned() {
        // Redundant with noFindings_notScanned but documents the distinction explicitly: an empty
        // findings list must never be read as "perfect TLS config", only "nothing known yet".
        assertThat(TlsGradeCalculator.calculate(List.of()).grade()).isNotEqualTo("A+");
    }

    @Test
    void expiredCertificate_gradeF() {
        TlsGradeCalculator.Result result = TlsGradeCalculator.calculate(
                List.of(new TlsFindingRow("TLS_CERT_EXPIRED", "TLS certificate expired", null, null)));
        assertThat(result.grade()).isEqualTo("F");
        assertThat(result.factors()).hasSize(1);
        assertThat(result.factors().get(0).ruleId()).isEqualTo("TLS_CERT_EXPIRED");
    }

    @Test
    void untrustedChain_gradeF() {
        assertThat(TlsGradeCalculator.calculate(List.of(
                        new TlsFindingRow("TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN", "title", null, null)))
                .grade())
                .isEqualTo("F");
    }

    @Test
    void hostnameMismatch_gradeF() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_CERT_HOSTNAME_MISMATCH", "title", null, null)))
                .grade())
                .isEqualTo("F");
    }

    @Test
    void sslv3Supported_gradeF() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_WEAK_PROTOCOL_SUPPORTED", "title", "SSLv3", null)))
                .grade())
                .isEqualTo("F");
    }

    @Test
    void poodleVulnerable_gradeF() {
        TlsGradeCalculator.Result result = TlsGradeCalculator.calculate(
                List.of(new TlsFindingRow("TLS_POODLE_VULNERABLE", "Vulnerable to POODLE (CVE-2014-3566)", null, null)));
        assertThat(result.grade()).isEqualTo("F");
        assertThat(result.factors()).hasSize(1);
        assertThat(result.factors().get(0).ruleId()).isEqualTo("TLS_POODLE_VULNERABLE");
    }

    @Test
    void tls1Supported_cappedB_notF() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_WEAK_PROTOCOL_SUPPORTED", "title", "TLSv1", null)))
                .grade())
                .isEqualTo("B");
    }

    @Test
    void nullCipherWeakSuite_gradeC() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_WEAK_CIPHER_SUITE", "title", null, "TLS_RSA_WITH_RC4_128_SHA")))
                .grade())
                .isEqualTo("C");
    }

    @Test
    void anonCipherSuite_gradeF() {
        assertThat(TlsGradeCalculator.calculate(List.of(
                        new TlsFindingRow("TLS_WEAK_CIPHER_SUITE", "title", null, "TLS_DH_anon_WITH_RC4_128_MD5")))
                .grade())
                .isEqualTo("F");
    }

    @Test
    void noForwardSecrecy_cappedB() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_NO_FORWARD_SECRECY", "title", null, null)))
                .grade())
                .isEqualTo("B");
    }

    @Test
    void weakSignatureAlgorithm_cappedB() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_CERT_SIGNATURE_ALGORITHM_WEAK", "title", null, null)))
                .grade())
                .isEqualTo("B");
    }

    @Test
    void keyTooShort_cappedC() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_CERT_KEY_TOO_SHORT", "title", null, null)))
                .grade())
                .isEqualTo("C");
    }

    @Test
    void unexpectedIssuer_cappedB() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_CT_UNEXPECTED_ISSUER", "title", null, null)))
                .grade())
                .isEqualTo("B");
    }

    @Test
    void tls13NotSupportedOnly_gradeAMinus() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_1_3_NOT_SUPPORTED", "title", null, null)))
                .grade())
                .isEqualTo("A-");
    }

    /** Nothing capped the grade, but HSTS isn't strong - plain A, not A+. */
    @Test
    void noCappingFindingButHstsWeak_gradeA() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_NO_HSTS", "title", null, null)))
                .grade())
                .isEqualTo("A");
    }

    @Test
    void hstsPreloadNotEligible_gradeA_notAPlus() {
        assertThat(TlsGradeCalculator.calculate(
                        List.of(new TlsFindingRow("TLS_HSTS_PRELOAD_NOT_ELIGIBLE", "title", null, null)))
                .grade())
                .isEqualTo("A");
    }

    /**
     * Documents the class's own known limitation (see its javadoc): a literally-perfect host
     * (zero open TLS findings) is indistinguishable from "never scanned" - both read as
     * NOT_SCANNED. A+ is not reachable with the current rule set at all: every recognized
     * TLS-category rule either caps the grade or is in A_PLUS_DISQUALIFYING_RULES.
     */
    @Test
    void literallyZeroFindings_isIndistinguishableFromNeverScanned_notAPlus() {
        assertThat(TlsGradeCalculator.calculate(List.of()).grade()).isNull();
    }

    /** TLS_CERT_EXPIRING_SOON doesn't cap the grade (it's a future risk, not a current weakness) but still keeps a host off the A+ tier, with a factor explaining why. */
    @Test
    void certExpiringSoon_doesNotCapGradeButBlocksAPlus() {
        TlsGradeCalculator.Result result = TlsGradeCalculator.calculate(
                List.of(new TlsFindingRow("TLS_CERT_EXPIRING_SOON", "title", null, null)));
        assertThat(result.grade()).isEqualTo("A");
        assertThat(result.factors()).hasSize(1);
        assertThat(result.factors().get(0).impact()).isEqualTo("Keeps grade at A rather than A+");
    }

    /**
     * No real current rule_id reaches this path (see the class's own "A+ not reachable" javadoc),
     * but the ladder mechanism itself must still work correctly for whenever a future rule that's
     * neither capping nor A+-disqualifying is added (e.g. a hypothetical "fully hardened" marker).
     */
    @Test
    void unrecognizedNonDisqualifyingRuleId_allowsAPlusThroughTheLadderMechanism() {
        TlsGradeCalculator.Result result = TlsGradeCalculator.calculate(
                List.of(new TlsFindingRow("TLS_SOME_FUTURE_INFO_ONLY_RULE", "title", null, null)));
        assertThat(result.grade()).isEqualTo("A+");
        assertThat(result.factors()).isEmpty();
    }

    @Test
    void worstCapWins_multipleFindingsTakeTheLowestGrade() {
        TlsGradeCalculator.Result result = TlsGradeCalculator.calculate(List.of(
                new TlsFindingRow("TLS_1_3_NOT_SUPPORTED", "title", null, null),
                new TlsFindingRow("TLS_NO_FORWARD_SECRECY", "title", null, null),
                new TlsFindingRow("TLS_CERT_EXPIRED", "title", null, null)));
        assertThat(result.grade()).isEqualTo("F");
        assertThat(result.factors()).hasSize(3);
    }

}
