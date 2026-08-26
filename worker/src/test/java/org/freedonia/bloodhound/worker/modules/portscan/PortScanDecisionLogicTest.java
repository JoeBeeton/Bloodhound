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
}
