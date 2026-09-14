package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class PortScanDecisionLogicTest {

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    private static Map<String, List<Integer>> ipv4(List<Integer> ports) {
        return Map.of("IPv4", ports);
    }

    @Test
    void noOpenPorts_noFindings() {
        assertThat(PortScanDecisionLogic.decide("example.com", ipv4(List.of()))).isEmpty();
    }

    @Test
    void webPortsOnly_noFindings() {
        assertThat(PortScanDecisionLogic.decide("example.com", ipv4(List.of(80, 443)))).isEmpty();
    }

    @Test
    void adminDbPort_flaggedHighWithHostPortAsset() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(3389)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
        assertThat(findings.get(0).severity().name()).isEqualTo("HIGH");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:3389");
        assertThat(findings.get(0).evidence()).containsEntry("addressFamilies", List.of("IPv4"));
    }

    @Test
    void unencryptedMgmtPort_flaggedMedium() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(23)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("PORT_OPEN_UNENCRYPTED_MGMT");
        assertThat(findings.get(0).severity().name()).isEqualTo("MEDIUM");
    }

    @Test
    void multipleOpenPorts_oneFindingEach() {
        assertThat(ruleIds(PortScanDecisionLogic.decide("example.com", ipv4(List.of(80, 3306, 21, 443, 6379)))))
                .containsExactlyInAnyOrder(
                        "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "PORT_OPEN_UNENCRYPTED_MGMT", "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
    }

    @Test
    void portOpenOnBothFamilies_singleFindingListingBoth() {
        List<RawFinding> findings =
                PortScanDecisionLogic.decide("example.com", Map.of("IPv4", List.of(3389), "IPv6", List.of(3389)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).evidence().get("addressFamilies")).isEqualTo(List.of("IPv4", "IPv6"));
    }

    @Test
    void portOpenOnlyOnIpv6_flaggedWithIpv6OnlyEvidence_thePreviouslyInvisibleCase() {
        List<RawFinding> findings =
                PortScanDecisionLogic.decide("example.com", Map.of("IPv4", List.of(), "IPv6", List.of(6379)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:6379");
        assertThat(findings.get(0).evidence()).containsEntry("addressFamilies", List.of("IPv6"));
    }

    @Test
    void differentPortsOpenPerFamily_bothReported() {
        List<RawFinding> findings =
                PortScanDecisionLogic.decide("example.com", Map.of("IPv4", List.of(3306), "IPv6", List.of(23)));
        assertThat(findings).hasSize(2);
        assertThat(ruleIds(findings))
                .containsExactlyInAnyOrder("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "PORT_OPEN_UNENCRYPTED_MGMT");
    }

    /** Below the threshold - each of a handful of admin ports still gets its own specific finding. */
    @Test
    void fourAdminPortsOpen_stillReportedIndividually_belowPromiscuousThreshold() {
        List<RawFinding> findings =
                PortScanDecisionLogic.decide("example.com", ipv4(List.of(3389, 3306, 5432, 27017)));
        assertThat(ruleIds(findings)).containsOnly("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
        assertThat(findings).hasSize(4);
    }

    /** The live incident this exists for: real hosts with all 9 ADMIN_DB_PORTS open at once. */
    @Test
    void allNineAdminPortsOpen_oneSinglePromiscuousFinding_notNineIndividualOnes() {
        List<RawFinding> findings = PortScanDecisionLogic.decide(
                "joinbeta.jaja.co.uk", ipv4(List.of(3389, 3306, 5432, 27017, 6379, 1433, 1521, 5900, 5984)));
        assertThat(ruleIds(findings)).containsExactly("NETWORK_PROMISCUOUS_PORT_RESPONSE");
        assertThat(findings.get(0).severity().name()).isEqualTo("INFO");
        assertThat(findings.get(0).evidence().get("openAdminPorts"))
                .isEqualTo(List.of(1433, 1521, 3306, 3389, 5432, 5900, 5984, 6379, 27017));
    }

    /** A non-admin unencrypted-mgmt port finding still fires normally alongside the promiscuous one. */
    @Test
    void promiscuousAdminPorts_plusAnUnencryptedMgmtPort_bothReported() {
        List<RawFinding> findings = PortScanDecisionLogic.decide(
                "example.com", ipv4(List.of(3389, 3306, 5432, 27017, 6379, 21)));
        assertThat(ruleIds(findings))
                .containsExactlyInAnyOrder("NETWORK_PROMISCUOUS_PORT_RESPONSE", "PORT_OPEN_UNENCRYPTED_MGMT");
    }
}
