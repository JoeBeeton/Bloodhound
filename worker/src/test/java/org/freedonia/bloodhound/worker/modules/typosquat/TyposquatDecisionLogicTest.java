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
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null)));

        assertThat(findings).hasSize(1);
        RawFinding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("TYPOSQUAT_DOMAIN_REGISTERED");
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.category()).isEqualTo(Category.BRAND);
        assertThat(finding.affectedAsset()).isEqualTo("exampl.com");
        assertThat(finding.evidence()).containsEntry("permutationType", "OMISSION");
        assertThat(finding.evidence()).containsEntry("resolvedIps", List.of("203.0.113.5"));
        assertThat(finding.evidence()).doesNotContainKey("registrationDate");
    }

    @Test
    void nonResolvingCandidateProducesNoFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(
                List.of(new TyposquatChecker.CheckedCandidate("exampl.com", "OMISSION", List.of(), null)));
        assertThat(findings).isEmpty();
    }

    @Test
    void registrationDateIncludedInEvidenceWhenAvailable() {
        Instant registered = Instant.parse("2026-01-01T00:00:00Z");
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "examp1e.com", "HOMOGLYPH", List.of("198.51.100.1"), registered)));
        assertThat(findings.get(0).evidence()).containsEntry("registrationDate", registered.toString());
    }

    @Test
    void mixOfResolvingAndNonResolvingOnlyFlagsTheResolvingOnes() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(
                new TyposquatChecker.CheckedCandidate("a.com", "OMISSION", List.of(), null),
                new TyposquatChecker.CheckedCandidate("b.com", "OMISSION", List.of("203.0.113.9"), null),
                new TyposquatChecker.CheckedCandidate("c.com", "OMISSION", List.of(), null)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).affectedAsset()).isEqualTo("b.com");
    }

    @Test
    void emptyInputProducesNoFindings() {
        assertThat(TyposquatDecisionLogic.decide(List.of())).isEmpty();
    }
}
