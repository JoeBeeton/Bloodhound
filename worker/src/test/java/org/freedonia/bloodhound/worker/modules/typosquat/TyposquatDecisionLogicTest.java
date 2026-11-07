package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.worker.modules.typosquat.TyposquatDecisionLogic.Disposition;
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
                        "exmaple.com", "TRANSPOSITION", List.of("198.51.100.7"), null, false, null, null, false)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).affectedAsset()).isEqualTo("exmaple.com");
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
    void mxConfigured_noCorroboration_addsHighEscalationAlongsideBaseOne() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, null, null, true)));

        assertThat(findings).extracting(RawFinding::ruleId)
                .containsExactlyInAnyOrder("TYPOSQUAT_DOMAIN_REGISTERED", "BRAND_TYPOSQUAT_MX_CONFIGURED");
        RawFinding escalation = findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_MX_CONFIGURED"))
                .findFirst()
                .orElseThrow();
        assertThat(escalation.severity()).isEqualTo(Severity.HIGH);
        assertThat(escalation.category()).isEqualTo(Category.BRAND);
        assertThat(escalation.affectedAsset()).isEqualTo("exampl.com");
    }

    @Test
    void mxConfigured_recentlyRegistered_isCritical() {
        Instant now = Instant.parse("2026-11-01T00:00:00Z");
        List<RawFinding> findings = TyposquatDecisionLogic.decide(
                List.of(new TyposquatChecker.CheckedCandidate(
                        "exampl.com", "OMISSION", List.of("203.0.113.5"), Instant.parse("2026-10-01T00:00:00Z"),
                        false, null, null, true)),
                now);
        assertThat(mxFinding(findings).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void mxConfigured_registeredYearsAgo_isHigh() {
        Instant now = Instant.parse("2026-11-01T00:00:00Z");
        List<RawFinding> findings = TyposquatDecisionLogic.decide(
                List.of(new TyposquatChecker.CheckedCandidate(
                        "exampl.com", "OMISSION", List.of("203.0.113.5"), Instant.parse("2009-03-01T00:00:00Z"),
                        false, null, null, true)),
                now);
        assertThat(mxFinding(findings).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void mxConfigured_visualClone_isCritical() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1}, 85, true)));
        assertThat(mxFinding(findings).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void brandControlledCandidate_producesNoFindingsAtAll() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(candidate(Disposition.BRAND_CONTROLLED)));
        assertThat(findings).isEmpty();
    }

    /** Regression: prod had ~69 parked/for-sale lookalikes flagged CRITICAL via parking MX and blank-page "clones". */
    @Test
    void parkedCandidate_singleLowRegistrationFinding_noEscalations() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(candidate(Disposition.PARKED)));

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("TYPOSQUAT_DOMAIN_REGISTERED");
        assertThat(findings.get(0).severity()).isEqualTo(Severity.LOW);
        assertThat(findings.get(0).evidence()).containsEntry("assessment", "PARKED");
        assertThat(findings.get(0).description()).contains("parked or listed for sale");
    }

    @Test
    void redirectsToBrandCandidate_singleInfoFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(candidate(Disposition.REDIRECTS_TO_BRAND)));
        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.INFO);
            assertThat(f.description()).contains("lands on this target's own site");
        });
    }

    @Test
    void corporateRegistrarCandidate_singleInfoFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(candidate(Disposition.CORPORATE_REGISTRAR)));
        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.severity()).isEqualTo(Severity.INFO);
            assertThat(f.description()).contains("brand-protection registrar");
        });
    }

    /** Live site, MX and a "clone" score - all would escalate an UNKNOWN candidate. */
    private static TyposquatChecker.CheckedCandidate candidate(Disposition disposition) {
        return new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1}, 99, true, disposition);
    }

    /**
     * Regression for a bug shipped with brand-control detection: monzo.com and revolut.com both use
     * Google Workspace, so any lookalike also on Google Workspace counted as brand-controlled and
     * was silently dropped.
     */
    @Test
    void isBrandControlled_sameSharedMailProvider_doesNotCount() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com",
                        List.of("aspmx.l.google.com", "alt1.aspmx.l.google.com"),
                        List.of("curt.ns.cloudflare.com"),
                        List.of("ASPMX.L.GOOGLE.COM."),
                        List.of("ns1.porkbun.com")))
                .isFalse();
    }

    @Test
    void isBrandControlled_sameDedicatedMailGateway_stillCounts() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com",
                        List.of("mx0a-0023b801.pphosted.com"),
                        List.of(),
                        List.of("mx0a-0023b801.pphosted.com"),
                        List.of()))
                .isTrue();
    }

    @Test
    void classify_parkingNameServers() {
        assertThat(classify(List.of(), List.of("ns1.afternic.com", "ns2.afternic.com"), null))
                .isEqualTo(Disposition.PARKED);
    }

    @Test
    void classify_parkingMailServer() {
        assertThat(classify(List.of("mx156.hostedmxserver.com"), List.of("ns1.porkbun.com"), null))
                .isEqualTo(Disposition.PARKED);
    }

    @Test
    void classify_parkingPage() {
        assertThat(classify(List.of(), List.of("ns1.porkbun.com"), new TyposquatPageProbe.PageInfo("exampl.com", true, false)))
                .isEqualTo(Disposition.PARKED);
    }

    @Test
    void classify_corporateBrandProtectionRegistrar() {
        assertThat(classify(List.of("custmx.cscdns.net"), List.of("dns1.cscdns.net", "dns2.cscdns.net"), null))
                .isEqualTo(Disposition.CORPORATE_REGISTRAR);
    }

    @Test
    void classify_homepageLandsOnTheBrand() {
        assertThat(classify(List.of(), List.of("ns1.porkbun.com"), new TyposquatPageProbe.PageInfo("www.example.com", false, false)))
                .isEqualTo(Disposition.REDIRECTS_TO_BRAND);
    }

    @Test
    void classify_homepageLandsOnALookalikeOfTheBrand_notTheBrand() {
        assertThat(classify(List.of(), List.of("ns1.porkbun.com"), new TyposquatPageProbe.PageInfo("evilexample.com", false, false)))
                .isEqualTo(Disposition.UNKNOWN);
    }

    @Test
    void classify_ordinaryHostingWithNoPageSignal_unknown() {
        assertThat(classify(List.of("mx.privateemail.com"), List.of("ns07.domaincontrol.com"), null))
                .isEqualTo(Disposition.UNKNOWN);
    }

    @Test
    void classify_brandControlledWinsOverEverythingElse() {
        assertThat(classify(List.of("mx1.example.com"), List.of("ns1.afternic.com"), null))
                .isEqualTo(Disposition.BRAND_CONTROLLED);
    }

    private static Disposition classify(List<String> mx, List<String> ns, TyposquatPageProbe.PageInfo page) {
        return TyposquatDecisionLogic.classify(
                "example.com", List.of("mx1.example.com"), List.of("a1-196.akam.net"), mx, ns, page);
    }

    @Test
    void isBrandControlled_mxIntoTheBrandsOwnMailServers() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com",
                        List.of("mx1.example.com.", "mx2.example.com."),
                        List.of("a1.akam.net."),
                        List.of("MX1.EXAMPLE.COM."),
                        List.of("ns-1.awsdns-01.org.")))
                .isTrue();
    }

    @Test
    void isBrandControlled_mxUnderTheBrandsDomainEvenIfNotOneOfItsCurrentMx() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com", List.of(), List.of(), List.of("inbound.example.com"), List.of()))
                .isTrue();
    }

    @Test
    void isBrandControlled_identicalDedicatedNameServers() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com",
                        List.of(),
                        List.of("a1-196.akam.net.", "a13-65.akam.net."),
                        List.of(),
                        List.of("a13-65.akam.net", "a1-196.akam.net")))
                .isTrue();
    }

    @Test
    void isBrandControlled_identicalButMassSharedNameServers_doesNotCount() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com",
                        List.of(),
                        List.of("dns1.registrar-servers.com.", "dns2.registrar-servers.com."),
                        List.of(),
                        List.of("dns1.registrar-servers.com.", "dns2.registrar-servers.com.")))
                .isFalse();
    }

    @Test
    void isBrandControlled_unrelatedMailAndNameServers() {
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com",
                        List.of("mx1.example.com"),
                        List.of("a1.akam.net"),
                        List.of("mx.hostedemail.com"),
                        List.of("ns1.mailbank.com")))
                .isFalse();
    }

    @Test
    void isBrandControlled_lookalikeOfTheBrandDomainItselfIsNotUnderIt() {
        // "evilexample.com" ends with "example.com" as a string but isn't a subdomain of it.
        assertThat(TyposquatDecisionLogic.isBrandControlled(
                        "example.com", List.of(), List.of(), List.of("mx.evilexample.com"), List.of()))
                .isFalse();
    }

    private static RawFinding mxFinding(List<RawFinding> findings) {
        return findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_MX_CONFIGURED"))
                .findFirst()
                .orElseThrow();
    }

    @Test
    void noMxConfigured_noEscalationFinding() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, null, null, false)));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("BRAND_TYPOSQUAT_MX_CONFIGURED");
    }

    /**
     * A security review found every live-site CRITICAL it spot-checked where the visual-similarity
     * comparison was weak or unavailable turned out to be an unrelated, coincidentally-named real
     * business or a parked page, not impersonation - "hosts a live page" alone, with no visual-clone
     * evidence, is downgraded to HIGH. No comparison available at all (screenshotter failure on the
     * real target, or the candidate's own screenshot not yet taken) is treated the same as a weak
     * match: there's no signal either way to justify CRITICAL.
     */
    @Test
    void liveScreenshotCaptured_noSimilarityComparisonAvailable_isHighNotCritical() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, null, false)));

        assertThat(findings).extracting(RawFinding::ruleId)
                .containsExactlyInAnyOrder("TYPOSQUAT_DOMAIN_REGISTERED", "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE");
        RawFinding escalation = findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_HOSTING_LIVE_SITE"))
                .findFirst()
                .orElseThrow();
        assertThat(escalation.severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void liveScreenshotCaptured_lowVisualSimilarity_isHighNotCritical() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, 15, false)));

        RawFinding escalation = findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_HOSTING_LIVE_SITE"))
                .findFirst()
                .orElseThrow();
        assertThat(escalation.severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void liveScreenshotCaptured_highVisualSimilarity_isCritical() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3}, 92, false)));

        RawFinding escalation = findings.stream()
                .filter(f -> f.ruleId().equals("BRAND_TYPOSQUAT_HOSTING_LIVE_SITE"))
                .findFirst()
                .orElseThrow();
        assertThat(escalation.severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void liveScreenshotCaptured_exactlyAtThreshold_isCritical() {
        List<RawFinding> findings = TyposquatDecisionLogic.decide(List.of(new TyposquatChecker.CheckedCandidate(
                "exampl.com", "OMISSION", List.of("203.0.113.5"), null, false, new byte[] {1, 2, 3},
                TyposquatDecisionLogic.CLONE_SIMILARITY_PERCENT, false)));

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
