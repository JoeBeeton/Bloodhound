package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class DeepPortScanDecisionLogicTest {

    private static PortDetail port(int id) {
        return new PortDetail(id, null, null, null, Map.of());
    }

    private static PortDetail port(int id, String name, String product, String version) {
        return new PortDetail(id, name, product, version, Map.of());
    }

    private static PortDetail portWithScript(int id, String scriptId, String output) {
        return new PortDetail(id, "ftp", "vsftpd", "3.0.3", Map.of(scriptId, output));
    }

    @Test
    void noOpenPorts_onlySummaryFindingWithZeroCount() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide("example.com", List.of());
        assertThat(findings).hasSize(1);
        RawFinding summary = findings.get(0);
        assertThat(summary.ruleId()).isEqualTo("NETWORK_FULL_PORT_SURFACE");
        assertThat(summary.severity().name()).isEqualTo("INFO");
        assertThat(summary.evidence()).containsEntry("openPortCount", 0);
    }

    @Test
    void adminDbPort_flaggedWithServiceEvidence() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(port(3306, "mysql", "MySQL", "8.0.34")));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity().name()).isEqualTo("HIGH");
        assertThat(finding.affectedAsset()).isEqualTo("example.com:3306");
        assertThat(finding.evidence()).containsEntry("product", "MySQL").containsEntry("version", "8.0.34");
        assertThat(finding.description()).contains("MySQL 8.0.34");
    }

    @Test
    void unencryptedMgmtPort_flaggedWithServiceEvidence() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(port(21, "ftp", "vsftpd", "3.0.3")));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("PORT_OPEN_UNENCRYPTED_MGMT"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity().name()).isEqualTo("MEDIUM");
        assertThat(finding.evidence()).containsEntry("product", "vsftpd");
    }

    @Test
    void ftpAnonScript_flagsCriticalAnonymousFtpFinding() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide(
                "example.com", List.of(portWithScript(21, "ftp-anon", "Anonymous FTP login allowed (FTP code 230)")));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_ANONYMOUS_FTP"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity().name()).isEqualTo("CRITICAL");
        assertThat(finding.description()).contains("Anonymous FTP login allowed (FTP code 230)");
        // Anonymous FTP is on an unencrypted-mgmt port too - both findings should fire.
        assertThat(findings.stream().map(RawFinding::ruleId))
                .contains("PORT_OPEN_UNENCRYPTED_MGMT", "NETWORK_ANONYMOUS_FTP", "NETWORK_FULL_PORT_SURFACE");
    }

    @Test
    void noFtpAnonScript_noAnonymousFtpFinding() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(portWithScript(443, "http-title", "Example")));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("NETWORK_ANONYMOUS_FTP");
    }

    @Test
    void fullPortSurfaceSummary_alwaysIncludesExactOpenPortCountAndList() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(port(80), port(443), port(8080)));
        RawFinding summary = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_FULL_PORT_SURFACE"))
                .findFirst()
                .orElseThrow();
        assertThat(summary.evidence()).containsEntry("openPortCount", 3);
        @SuppressWarnings("unchecked")
        List<Integer> ports = (List<Integer>) summary.evidence().get("ports");
        assertThat(ports).containsExactlyInAnyOrder(80, 443, 8080);
    }

    @Test
    void webPortsOnly_noAdminOrMgmtFindings_justSummary() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide("example.com", List.of(port(80), port(443)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("NETWORK_FULL_PORT_SURFACE");
    }
}
