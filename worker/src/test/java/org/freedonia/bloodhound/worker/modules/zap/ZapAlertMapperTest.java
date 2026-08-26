package org.freedonia.bloodhound.worker.modules.zap;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.junit.jupiter.api.Test;

class ZapAlertMapperTest {

    private static ZapAlert alert(String pluginId, String risk, String url) {
        return new ZapAlert(
                pluginId, "Alert " + pluginId, risk, "High", "description", "solution", "reference", url, "", "");
    }

    @Test
    void mapsAllFourRiskLevels() {
        List<RawFinding> findings = ZapAlertMapper.map(List.of(
                alert("1", "High", "http://juiceshop.local/a"),
                alert("2", "Medium", "http://juiceshop.local/b"),
                alert("3", "Low", "http://juiceshop.local/c"),
                alert("4", "Informational", "http://juiceshop.local/d")));

        assertThat(findings).hasSize(4);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.get(1).severity()).isEqualTo(Severity.MEDIUM);
        assertThat(findings.get(2).severity()).isEqualTo(Severity.LOW);
        assertThat(findings.get(3).severity()).isEqualTo(Severity.INFO);
    }

    @Test
    void unrecognizedRiskDefaultsToInfoRatherThanThrowing() {
        List<RawFinding> findings = ZapAlertMapper.map(List.of(alert("1", "SomeFutureRiskLevel", "http://x/")));

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.INFO);
    }

    @Test
    void everyFindingUsesWebAppCategoryOutsideTheScoringWeightTable() {
        List<RawFinding> findings = ZapAlertMapper.map(List.of(alert("1", "High", "http://x/")));

        assertThat(findings.get(0).category()).isEqualTo(Category.WEB_APP);
    }

    @Test
    void ruleIdIsPluginIdPrefixed() {
        List<RawFinding> findings = ZapAlertMapper.map(List.of(alert("40012", "High", "http://x/")));

        assertThat(findings.get(0).ruleId()).isEqualTo("ZAP_ALERT_40012");
    }

    @Test
    void dedupesSamePluginAndUrl() {
        // ZAP can report the same (plugin, url) pair more than once - e.g. once
        // per parameter tested - the module should collapse these to one finding.
        List<RawFinding> findings = ZapAlertMapper.map(List.of(
                alert("40018", "High", "http://juiceshop.local/rest/user/login"),
                alert("40018", "High", "http://juiceshop.local/rest/user/login"),
                alert("40018", "High", "http://juiceshop.local/rest/products/search")));

        assertThat(findings).hasSize(2);
    }

    @Test
    void evidenceCarriesSolutionReferenceParamAndConfidence() {
        ZapAlert alert = new ZapAlert(
                "40012",
                "Cross Site Scripting (Reflected)",
                "High",
                "High",
                "XSS description",
                "Sanitize user input",
                "https://owasp.org/xss",
                "http://juiceshop.local/search?q=%3Cscript%3E",
                "q",
                "<script>alert(1)</script>");

        List<RawFinding> findings = ZapAlertMapper.map(List.of(alert));

        assertThat(findings.get(0).evidence())
                .containsEntry("solution", "Sanitize user input")
                .containsEntry("reference", "https://owasp.org/xss")
                .containsEntry("param", "q")
                .containsEntry("confidence", "High")
                .containsEntry("evidence", "<script>alert(1)</script>");
    }

    @Test
    void blankOptionalFieldsAreOmittedFromEvidenceRatherThanStoredEmpty() {
        List<RawFinding> findings = ZapAlertMapper.map(List.of(alert("1", "High", "http://x/")));

        // alert() helper sets param/evidence to "" - those shouldn't pollute
        // evidence with empty-string noise.
        assertThat(findings.get(0).evidence()).doesNotContainKeys("param", "evidence");
    }

    @Test
    void missingNameFallsBackToPluginIdBasedTitleRatherThanNull() {
        ZapAlert alert = new ZapAlert("999", null, "Low", null, null, null, null, "http://x/", null, null);

        List<RawFinding> findings = ZapAlertMapper.map(List.of(alert));

        assertThat(findings.get(0).title()).contains("999");
        assertThat(findings.get(0).description()).isEmpty();
    }
}
