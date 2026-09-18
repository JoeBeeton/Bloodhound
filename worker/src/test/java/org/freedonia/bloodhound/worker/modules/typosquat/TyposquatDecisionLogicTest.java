package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.junit.jupiter.api.Test;

class TyposquatDecisionLogicTest {

    @Test
    void resolvingCandidateProducesAHighSeverityBrandFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, null, null, false)));

        assertThat(findings).hasSize(1);
        RawFinding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("TYPOSQUAT_DOMAIN_REGISTERED");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.category()).isEqualTo(Category.BRAND);
        assertThat(finding.affectedAsset()).isEqualTo("exampl.com");
        assertThat(finding.evidence()).containsEntry("permutationType", "OMISSION");
        assertThat(finding.evidence()).containsEntry("resolvedIps", List.of("203.0.113.5"));
        assertThat(finding.evidence()).doesNotContainKey("registrationDate");
        assertThat(finding.evidence()).doesNotContainKey("visualSimilarityPercent");
    }

    @Test
    void nonResolvingCandidateProducesNoFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(
                new TyposquatChecker.CheckedCandidate("exampl.com", "OMISSION", List.of(), null, false, null, null, false)));
        assertThat(findings).isEmpty();
    }

    @Test
    void registrationDateIncludedInEvidenceWhenAvailable() {
        Instant registered = Instant.parse("2026-01-01T00:00:00Z");
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "examp1e.com", "HOMOGLYPH", List.of("198.51.100.1"), registered, false, null, null, false)));
        assertThat(findings.get(0).evidence()).containsEntry("registrationDate", registered.toString());
    }

    @Test
    void mixOfResolvingAndNonResolvingOnlyFlagsTheResolvingOnes() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(
                new TyposquatChecker.CheckedCandidate("a.com", "OMISSION", List.of(), null, false, null, null, false),
                new TyposquatChecker.CheckedCandidate(
                        "b.com", "OMISSION", List.of("203.0.113.9"), null, false, null, null, false),
                new TyposquatChecker.CheckedCandidate("c.com", "OMISSION", List.of(), null, false, null, null, false)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).affectedAsset()).isEqualTo("b.com");
    }

    @Test
    void emptyInputProducesNoFindings() {
        assertThat(TyposquatDecisionLogic.decide(List.of())).isEmpty();
    }

    /**
     * Regression test for a real false positive: example.c-o.uk was flagged as a registered
     * lookalike of example.co.uk, but c-o.uk (a real, separately-registered domain a squatter
     * wildcards to catch typos of "co.uk" itself) resolves for literally any subdomain -
     * "example" was never specifically registered by anyone. A candidate that resolves purely
     * because of that must never produce a finding, even though resolvedIps is non-empty.
     */
    @Test
    void resolvingCandidateFlaggedAsWildcardArtifact_producesNoFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "example.c-o.uk", "HYPHENATION", List.of("203.0.113.5"), null, true, null, null, false)));
        assertThat(findings).isEmpty();
    }

    @Test
    void wildcardArtifactAndGenuineCandidateMixed_onlyGenuineOneFlagged() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(
                new TyposquatChecker.CheckedCandidate(
                        "example.c-o.uk", "HYPHENATION", List.of("203.0.113.5"), null, true, null, null, false),
                new TyposquatChecker.CheckedCandidate(
                        "jjaa.com", "TRANSPOSITION", List.of("198.51.100.7"), null, false, null, null, false)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).affectedAsset()).isEqualTo("jjaa.com");
    }

    @Test
    void highVisualSimilarity_includedInEvidenceAndFlaggedAsStrongSignalInDescription() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, 92, false)));

        RawFinding finding = findings.get(0);
        assertThat(finding.evidence()).containsEntry("visualSimilarityPercent", 92);
        assertThat(finding.description()).contains("92%").contains("strong additional signal");
    }

    @Test
    void lowVisualSimilarity_includedInEvidence_describedAsWeakMatch() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, 15, false)));

        RawFinding finding = findings.get(0);
        assertThat(finding.evidence()).containsEntry("visualSimilarityPercent", 15);
        assertThat(finding.description()).contains("15%").contains("weak visual match");
    }

    @Test
    void mxConfigured_addsEscalationFindingAlongsideBaseOne() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, null, null, true)));

        assertThat(findings).extracting(RawFinding::ruleId)
                .containsExactlyInAnyOrder("TYPOSQUAT_DOMAIN_REGISTERED", "BRAND_TYPOSQUAT_MX_CONFIGURED");
        RawFinding escalation = findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_MX_CONFIGURED"))
                .findFirst()
                .orElseThrow();
        assertThat(escalation.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(escalation.category()).isEqualTo(Category.BRAND);
        assertThat(escalation.affectedAsset()).isEqualTo("exampl.com");
    }

    @Test
    void noMxConfigured_noEscalationFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, null, null, false)));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("BRAND_TYPOSQUAT_MX_CONFIGURED");
    }

    @Test
    void liveScreenshotCaptured_addsHostingLiveSiteEscalation() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, null, false)));

        assertThat(findings).extracting(RawFinding::ruleId)
                .containsExactlyInAnyOrder("TYPOSQUAT_DOMAIN_REGISTERED", "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE");
        RawFinding escalation = findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_HOSTING_LIVE_SITE"))
                .findFirst()
                .orElseThrow();
        assertThat(escalation.severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void noScreenshotCaptured_noHostingLiveSiteEscalation() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, null, null, false)));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("BRAND_TYPOSQUAT_HOSTING_LIVE_SITE");
    }

    @Test
    void mxConfiguredAndLiveSite_bothEscalationsFireAlongsideBase() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, 92, true)));
        assertThat(findings).extracting(RawFinding::ruleId).containsExactlyInAnyOrder(
                "TYPOSQUAT_DOMAIN_REGISTERED", "BRAND_TYPOSQUAT_MX_CONFIGURED", "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE");
    }
}
