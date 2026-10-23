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
                "joinbeta.example.co.uk", ipv4(List.of(3389, 3306, 5432, 27017, 6379, 1433, 1521, 5900, 5984)));
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

    @Test
    void smbPort445_flaggedCriticalAsSmbNetbiosExposed_notGenericAdminService() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(445)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("NETWORK_SMB_NETBIOS_EXPOSED");
        assertThat(findings.get(0).severity().name()).isEqualTo("CRITICAL");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:445");
    }

    @Test
    void netbiosPort139_flaggedAsSmbNetbiosExposed() {
        assertThat(ruleIds(PortScanDecisionLogic.decide("example.com", ipv4(List.of(139)))))
                .containsExactly("NETWORK_SMB_NETBIOS_EXPOSED");
    }

    @Test
    void msrpcPort135_flaggedAsSmbNetbiosExposed() {
        assertThat(ruleIds(PortScanDecisionLogic.decide("example.com", ipv4(List.of(135)))))
                .containsExactly("NETWORK_SMB_NETBIOS_EXPOSED");
    }

    @Test
    void memcachedPort11211_flaggedCriticalAsMemcachedExposed_notGenericAdminService() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(11211)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("NETWORK_MEMCACHED_EXPOSED");
        assertThat(findings.get(0).severity().name()).isEqualTo("CRITICAL");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:11211");
    }

    @Test
    void mongoShardPort27018_flaggedSameAsStandalone27017() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(27018)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:27018");
    }

    @Test
    void elasticsearchTransportPort9300_flagged() {
        assertThat(ruleIds(PortScanDecisionLogic.decide("example.com", ipv4(List.of(9300)))))
                .containsExactly("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
    }

    @Test
    void kafkaBrokerPort9092_flagged() {
        assertThat(ruleIds(PortScanDecisionLogic.decide("example.com", ipv4(List.of(9092)))))
                .containsExactly("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE");
    }

    @Test
    void pop3Port_flaggedAsCleartextMailProtocolExposed() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(110)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED");
        assertThat(findings.get(0).severity().name()).isEqualTo("MEDIUM");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:110");
    }

    @Test
    void imapPort_flaggedAsCleartextMailProtocolExposed() {
        assertThat(ruleIds(PortScanDecisionLogic.decide("example.com", ipv4(List.of(143)))))
                .containsExactly("NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED");
    }

    @Test
    void secureMailPorts_notFlagged() {
        // 995 (POP3S) and 993 (IMAPS) are the already-TLS-wrapped variants - not this rule's gap.
        assertThat(PortScanDecisionLogic.decide("example.com", ipv4(List.of(995, 993)))).isEmpty();
    }

    @Test
    void smbPortsIncludedInPromiscuousPortPattern_notDoubleFlagged() {
        // SMB/NetBIOS/RPC ports share ADMIN_DB_PORTS' own promiscuous-port false-positive
        // protection - if they're part of a 5+-port "answers on everything" pattern, they must
        // not ALSO get their own specific (and now even more alarming, CRITICAL) finding.
        List<RawFinding> findings = PortScanDecisionLogic.decide(
                "example.com", ipv4(List.of(3389, 3306, 5432, 27017, 445)));
        assertThat(ruleIds(findings)).containsExactly("NETWORK_PROMISCUOUS_PORT_RESPONSE");
        assertThat(findings.get(0).evidence().get("openAdminPorts")).isEqualTo(List.of(445, 3306, 3389, 5432, 27017));
    }

    /**
     * A rules-parity review found SSH (22) was scanned but produced no finding either way when
     * open - unlike Docker/Elasticsearch, which get a real application-level probe elsewhere, SSH
     * had no Tier 1 signal at all.
     */
    @Test
    void sshPort_flaggedAsReachable_informational() {
        List<RawFinding> findings = PortScanDecisionLogic.decide("example.com", ipv4(List.of(22)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("NETWORK_SSH_PORT_REACHABLE");
        assertThat(findings.get(0).severity().name()).isEqualTo("INFO");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com:22");
    }
}
