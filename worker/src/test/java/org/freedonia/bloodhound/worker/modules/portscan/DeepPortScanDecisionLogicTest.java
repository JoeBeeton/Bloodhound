package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class DeepPortScanDecisionLogicTest {

    private static PortDetail port(int id) {
        return new PortDetail(id, null, null, null, Map.of(), "IPv4");
    }

    private static PortDetail port(int id, String name, String product, String version) {
        return new PortDetail(id, name, product, version, Map.of(), "IPv4");
    }

    private static PortDetail port(int id, String family) {
        return new PortDetail(id, null, null, null, Map.of(), family);
    }

    private static PortDetail portWithScript(int id, String scriptId, String output) {
        return new PortDetail(id, "ftp", "vsftpd", "3.0.3", Map.of(scriptId, output), "IPv4");
    }

    private static PortDetail sshPortWithWeakAlgorithms(Map<String, String> scriptOutputs) {
        return new PortDetail(22, "ssh", "OpenSSH", "6.6.1p1", scriptOutputs, "IPv4");
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
        assertThat(finding.evidence()).containsEntry("addressFamilies", List.of("IPv4"));
        assertThat(finding.description()).contains("MySQL 8.0.34");
    }

    @Test
    void smbPort445_flaggedAsSmbNetbiosExposed_notGenericAdminService() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(port(445, "microsoft-ds", "Samba", "4.15.0")));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_SMB_NETBIOS_EXPOSED"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity().name()).isEqualTo("CRITICAL");
        assertThat(finding.affectedAsset()).isEqualTo("example.com:445");
        assertThat(finding.description()).contains("Samba 4.15.0");
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
    }

    @Test
    void pop3Port_flaggedAsCleartextMailProtocolExposed() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(port(110, "pop3", "Dovecot", "2.3.19")));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity().name()).isEqualTo("MEDIUM");
        assertThat(finding.affectedAsset()).isEqualTo("example.com:110");
        assertThat(finding.description()).contains("Dovecot 2.3.19");
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
    void sshWeakAlgorithmScriptOutputs_flagsHighSeverityFinding() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide(
                "example.com",
                List.of(sshPortWithWeakAlgorithms(Map.of(
                        "ssh-weak-kex", "diffie-hellman-group1-sha1", "ssh-weak-hostkey", "ssh-rsa"))));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity().name()).isEqualTo("HIGH");
        assertThat(finding.affectedAsset()).isEqualTo("example.com:22");
        assertThat(finding.evidence())
                .containsEntry("weakkexAlgorithms", "diffie-hellman-group1-sha1")
                .containsEntry("weakhostkeyAlgorithms", "ssh-rsa");
        assertThat(finding.description()).contains("diffie-hellman-group1-sha1").contains("ssh-rsa");
    }

    @Test
    void sshNoWeakAlgorithmScriptOutputs_noFinding() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(sshPortWithWeakAlgorithms(Map.of())));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED");
    }

    @Test
    void sshWeakAlgorithmScriptOutputsPresentButBlank_noFinding() {
        // DeepPortScanModule only ever puts a key in scriptOutputs when its weak list is non-empty,
        // but guard the blank-value case defensively too, same tolerant style as the rest of this class.
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide(
                "example.com", List.of(sshPortWithWeakAlgorithms(Map.of("ssh-weak-kex", ""))));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED");
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

    @Test
    void samePortOpenOnBothFamilies_singleFindingListingBoth() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide(
                "example.com", List.of(port(3389, "IPv4"), port(3389, "IPv6")));
        List<RawFinding> adminFindings = findings.stream()
                .filter(f -> f.ruleId().equals("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE"))
                .toList();
        assertThat(adminFindings).hasSize(1);
        assertThat(adminFindings.get(0).evidence()).containsEntry("addressFamilies", List.of("IPv4", "IPv6"));
        // The full-port-surface count is distinct ports, not one-per-family-entry.
        RawFinding summary = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_FULL_PORT_SURFACE"))
                .findFirst()
                .orElseThrow();
        assertThat(summary.evidence()).containsEntry("openPortCount", 1);
    }

    @Test
    void portOpenOnlyOnIpv6_flaggedWithIpv6OnlyEvidence_thePreviouslyInvisibleCase() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide("example.com", List.of(port(6379, "IPv6")));
        RawFinding finding = findings.stream()
                .filter(f -> f.ruleId().equals("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.evidence()).containsEntry("addressFamilies", List.of("IPv6"));
    }

    @Test
    void differentPortsOpenPerFamily_bothReportedSeparately() {
        List<RawFinding> findings =
                DeepPortScanDecisionLogic.decide("example.com", List.of(port(3306, "IPv4"), port(23, "IPv6")));
        assertThat(findings.stream().map(RawFinding::ruleId))
                .contains("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "PORT_OPEN_UNENCRYPTED_MGMT");
    }

    /** The live incident this exists for, at the deep-scan layer: joinbeta.jaja.co.uk/pioneers.jaja.co.uk
     * both showed every one of these 9 ports open at once with zero real service identification behind any of them. */
    @Test
    void allNineAdminPortsOpen_oneSinglePromiscuousFinding_notNineIndividualOnes() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide(
                "joinbeta.jaja.co.uk",
                List.of(
                        port(3389), port(3306), port(5432), port(27017), port(6379),
                        port(1433), port(1521), port(5900), port(5984)));
        assertThat(findings.stream().map(RawFinding::ruleId))
                .contains("NETWORK_PROMISCUOUS_PORT_RESPONSE")
                .doesNotContain("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
        RawFinding promiscuous = findings.stream()
                .filter(f -> f.ruleId().equals("NETWORK_PROMISCUOUS_PORT_RESPONSE"))
                .findFirst()
                .orElseThrow();
        assertThat(promiscuous.severity().name()).isEqualTo("INFO");
    }

    /** Even with real product/version identification, the promiscuous pattern still wins - that many
     * unrelated vendor protocols "identifying" at once is itself the implausible signal. */
    @Test
    void allNineAdminPortsOpenWithServiceEvidence_stillOnePromiscuousFinding() {
        List<RawFinding> findings = DeepPortScanDecisionLogic.decide(
                "example.com",
                List.of(
                        port(3389, "rdp", "Windows RDP", null), port(3306, "mysql", "MySQL", "8.0"),
                        port(5432, "postgresql", "PostgreSQL", "14"), port(27017, "mongodb", "MongoDB", null),
                        port(6379, "redis", "Redis", null), port(1433, "mssql", "MSSQL", null),
                        port(1521, "oracle", "Oracle", null), port(5900, "vnc", "VNC", null),
                        port(5984, "couchdb", "CouchDB", null)));
        assertThat(findings.stream().map(RawFinding::ruleId))
                .contains("NETWORK_PROMISCUOUS_PORT_RESPONSE")
                .doesNotContain("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
    }
}
