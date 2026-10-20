package org.freedonia.bloodhound.worker.modules.dns;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class DnsZoneDecisionLogicTest {

    @Test
    void wellConfiguredNameserver_producesNoFindings() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("ns1.example.com", false, 0, true)));
        assertThat(findings).isEmpty();
    }

    @Test
    void axfrAllowed_flaggedCriticalWithNameserverAsAffectedAsset() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("ns1.example.com", true, 42, true)));
        assertThat(findings).hasSize(1);
        RawFinding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("DNS_ZONE_TRANSFER_ALLOWED");
        assertThat(f.severity().name()).isEqualTo("CRITICAL");
        assertThat(f.affectedAsset()).isEqualTo("ns1.example.com");
        assertThat(f.evidence()).containsEntry("recordCount", 42);
    }

    @Test
    void axfrRefused_notFlagged() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("ns1.example.com", false, 0, true)));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("DNS_ZONE_TRANSFER_ALLOWED");
    }

    @Test
    void nameserverNotAuthoritative_flaggedAsLameDelegation() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("ns2.example.com", false, 0, false)));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("DNS_NS_LAME_DELEGATION");
        assertThat(findings.get(0).severity().name()).isEqualTo("MEDIUM");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("ns2.example.com");
    }

    @Test
    void mixedNameservers_eachEvaluatedIndependently() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(List.of(
                new DnsZoneFetcher.NsCheckResult("good.example.com", false, 0, true),
                new DnsZoneFetcher.NsCheckResult("vulnerable.example.com", true, 10, true),
                new DnsZoneFetcher.NsCheckResult("lame.example.com", false, 0, false)));
        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(RawFinding::affectedAsset)
                .containsExactlyInAnyOrder("vulnerable.example.com", "lame.example.com");
    }

    @Test
    void nameserverBothVulnerableAndLame_producesBothFindings() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("bad.example.com", true, 5, false)));
        assertThat(findings).extracting(RawFinding::ruleId)
                .containsExactlyInAnyOrder("DNS_ZONE_TRANSFER_ALLOWED", "DNS_NS_LAME_DELEGATION");
    }

    @Test
    void noNameservers_producesNoFindings() {
        assertThat(DnsZoneDecisionLogic.decide(List.of())).isEmpty();
    }

    /** An unreachable nameserver is no evidence either way - never lame, never a transfer. */
    @Test
    void unreachableNameserver_yieldsNoFindingsAtAll() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("blocked.example.com", false, 0, false, false)));
        assertThat(findings).isEmpty();
    }

    @Test
    void openResolver_flaggedMedium() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("ns1.example.com", false, 0, true, true, true)));
        assertThat(findings).hasSize(1);
        RawFinding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("NETWORK_DNS_OPEN_RESOLVER");
        assertThat(f.severity().name()).isEqualTo("MEDIUM");
        assertThat(f.affectedAsset()).isEqualTo("ns1.example.com");
    }

    @Test
    void notOpenResolver_notFlagged() {
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("ns1.example.com", false, 0, true, true, false)));
        assertThat(findings).extracting(RawFinding::ruleId).doesNotContain("NETWORK_DNS_OPEN_RESOLVER");
    }

    @Test
    void unreachableNameserver_neverFlaggedAsOpenResolverEvenIfTrue() {
        // reachable=false short-circuits every check in decide() before openResolver is even
        // consulted - defensive: an unreachable nameserver's fetch-side code never actually sets
        // openResolver=true in practice, but the interpretation layer must not assume that.
        List<RawFinding> findings = DnsZoneDecisionLogic.decide(
                List.of(new DnsZoneFetcher.NsCheckResult("blocked.example.com", false, 0, false, false, true)));
        assertThat(findings).isEmpty();
    }
}
