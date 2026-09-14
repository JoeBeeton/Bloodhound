package org.freedonia.bloodhound.worker.modules.nuclei;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class NucleiFindingMapperTest {

    private static NucleiFinding finding(String templateId, String severity, String matchedAt) {
        return new NucleiFinding(templateId, "Test Finding", severity, "A test description.", "example.com",
                matchedAt, "https://example.org/ref", List.of(), null, null, null);
    }

    @Test
    void emptyResults_noFindings() {
        assertThat(NucleiFindingMapper.map(List.of())).isEmpty();
    }

    @Test
    void basicResult_mappedWithRuleIdPrefixedTemplateId() {
        List<RawFinding> findings =
                NucleiFindingMapper.map(List.of(finding("waf-detect", "info", "http://example.com")));
        assertThat(findings).hasSize(1);
        RawFinding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("NUCLEI_waf-detect");
        assertThat(f.severity().name()).isEqualTo("INFO");
        assertThat(f.category().name()).isEqualTo("WEB_APP");
        assertThat(f.affectedAsset()).isEqualTo("http://example.com");
        assertThat(f.title()).isEqualTo("Test Finding");
        assertThat(f.evidence()).containsEntry("reference", "https://example.org/ref");
    }

    @Test
    void severityMapping_allFiveLevelsPlusUnknown() {
        assertThat(NucleiFindingMapper.severityFor("critical").name()).isEqualTo("CRITICAL");
        assertThat(NucleiFindingMapper.severityFor("high").name()).isEqualTo("HIGH");
        assertThat(NucleiFindingMapper.severityFor("medium").name()).isEqualTo("MEDIUM");
        assertThat(NucleiFindingMapper.severityFor("low").name()).isEqualTo("LOW");
        assertThat(NucleiFindingMapper.severityFor("info").name()).isEqualTo("INFO");
        assertThat(NucleiFindingMapper.severityFor("unknown").name()).isEqualTo("INFO");
        assertThat(NucleiFindingMapper.severityFor(null).name()).isEqualTo("INFO");
    }

    @Test
    void severityMapping_caseInsensitive() {
        assertThat(NucleiFindingMapper.severityFor("CRITICAL").name()).isEqualTo("CRITICAL");
        assertThat(NucleiFindingMapper.severityFor("High").name()).isEqualTo("HIGH");
    }

    @Test
    void duplicateTemplateAndUrl_dedupedToOneFinding() {
        List<NucleiFinding> results = List.of(
                finding("waf-detect", "info", "http://example.com"),
                finding("waf-detect", "info", "http://example.com"));
        assertThat(NucleiFindingMapper.map(results)).hasSize(1);
    }

    @Test
    void sameTemplateDifferentUrl_bothKept() {
        List<NucleiFinding> results = List.of(
                finding("exposed-panel", "medium", "http://example.com/admin"),
                finding("exposed-panel", "medium", "http://example.com/manager"));
        assertThat(NucleiFindingMapper.map(results)).hasSize(2);
    }

    @Test
    void nullMatchedAt_fallsBackToHost() {
        NucleiFinding result =
                new NucleiFinding("t", "Name", "info", "desc", "example.com", null, null, List.of(), null, null, null);
        RawFinding f = NucleiFindingMapper.map(List.of(result)).get(0);
        assertThat(f.affectedAsset()).isEqualTo("example.com");
    }

    @Test
    void missingName_fallsBackToTemplateIdInTitle() {
        NucleiFinding result = new NucleiFinding(
                "mystery-template", null, "low", null, "example.com", "http://example.com", null, List.of(), null, null, null);
        RawFinding f = NucleiFindingMapper.map(List.of(result)).get(0);
        assertThat(f.title()).isEqualTo("Nuclei finding (template mystery-template)");
        assertThat(f.description()).isEqualTo("");
    }

    @Test
    void cveIdAndExtractedResults_includedInEvidenceWhenPresent() {
        NucleiFinding result = new NucleiFinding(
                "cve-2021-12345", "Some CVE", "critical", "desc", "example.com", "http://example.com",
                null, List.of("v1.2.3"), "curl ...", "CVE-2021-12345", null);
        RawFinding f = NucleiFindingMapper.map(List.of(result)).get(0);
        assertThat(f.evidence()).containsEntry("cveId", "CVE-2021-12345");
        assertThat(f.evidence()).containsEntry("curlCommand", "curl ...");
        assertThat(f.evidence().get("extractedResults")).isEqualTo(List.of("v1.2.3"));
    }

    /** waf-detect's matcher name IS the vendor identified - see NucleiFindingMapper's own comment. */
    @Test
    void matcherName_includedInEvidenceWhenPresent() {
        NucleiFinding result = new NucleiFinding(
                "waf-detect", "WAF Detection", "info", "desc", "asda.jaja.co.uk", "https://asda.jaja.co.uk",
                null, List.of(), null, null, "cloudflare");
        RawFinding f = NucleiFindingMapper.map(List.of(result)).get(0);
        assertThat(f.evidence()).containsEntry("matcherName", "cloudflare");
    }

    @Test
    void nullMatcherName_omittedFromEvidence() {
        RawFinding f = NucleiFindingMapper.map(List.of(finding("tech-detect", "info", "http://example.com")))
                .get(0);
        assertThat(f.evidence()).doesNotContainKey("matcherName");
    }
}
