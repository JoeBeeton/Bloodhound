package org.freedonia.bloodhound.worker.modules.whois;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class WhoisDecisionLogicTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private static WhoisFields fieldsWithExpiry(Instant expiry) {
        return new WhoisFields(
                "Some Registrar", NOW.minus(1000, ChronoUnit.DAYS), expiry, null, List.of(), Map.of(), false, List.of());
    }

    @Test
    void noExpiryDate_noFindings() {
        WhoisFields fields = new WhoisFields(null, null, null, null, List.of(), Map.of(), false, List.of());
        assertThat(WhoisDecisionLogic.decide("example.com", fields, NOW)).isEmpty();
    }

    @Test
    void expiryFarInFuture_noFindings() {
        assertThat(WhoisDecisionLogic.decide("example.com", fieldsWithExpiry(NOW.plus(200, ChronoUnit.DAYS)), NOW))
                .isEmpty();
    }

    @Test
    void expiryWithin30Days_flaggedHigh() {
        List<RawFinding> findings = WhoisDecisionLogic.decide("example.com", fieldsWithExpiry(NOW.plus(10, ChronoUnit.DAYS)), NOW);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("WHOIS_EXPIRY_APPROACHING");
        assertThat(findings.get(0).severity().name()).isEqualTo("HIGH");
        assertThat(findings.get(0).affectedAsset()).isEqualTo("example.com");
    }

    @Test
    void expiryAlreadyPast_stillFlagged() {
        assertThat(WhoisDecisionLogic.decide("example.com", fieldsWithExpiry(NOW.minus(1, ChronoUnit.DAYS)), NOW))
                .hasSize(1);
    }

    @Test
    void expiryExactlyAt30Days_notFlagged() {
        assertThat(WhoisDecisionLogic.decide("example.com", fieldsWithExpiry(NOW.plus(30, ChronoUnit.DAYS)), NOW))
                .isEmpty();
    }

    private static WhoisFields fieldsWithStatus(List<String> statusCodes) {
        return new WhoisFields("Some Registrar", NOW.minus(1000, ChronoUnit.DAYS), null, null, List.of(), Map.of(),
                false, statusCodes);
    }

    @Test
    void noTransferProhibitedStatus_flaggedMedium() {
        List<RawFinding> findings =
                WhoisDecisionLogic.decide("example.com", fieldsWithStatus(List.of("active")), NOW);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("WHOIS_NO_TRANSFER_LOCK");
        assertThat(findings.get(0).severity().name()).isEqualTo("MEDIUM");
    }

    @Test
    void clientTransferProhibitedPresent_notFlagged() {
        assertThat(WhoisDecisionLogic.decide(
                        "example.com", fieldsWithStatus(List.of("active", "clientTransferProhibited")), NOW))
                .isEmpty();
    }

    @Test
    void transferProhibitedCaseInsensitive_notFlagged() {
        assertThat(WhoisDecisionLogic.decide(
                        "example.com", fieldsWithStatus(List.of("clienttransferprohibited")), NOW))
                .isEmpty();
    }

    @Test
    void transferProhibitedRdapSpacedForm_alsoNotFlagged() {
        // RDAP's real EPP status vocabulary is spaced lowercase ("client transfer prohibited"),
        // distinct from raw WHOIS text's concatenated camelCase form - both must be recognized.
        assertThat(WhoisDecisionLogic.decide(
                        "example.com", fieldsWithStatus(List.of("client transfer prohibited")), NOW))
                .isEmpty();
    }

    @Test
    void emptyStatusCodes_unknownNotUnlocked_notFlagged() {
        assertThat(WhoisDecisionLogic.decide("example.com", fieldsWithStatus(List.of()), NOW)).isEmpty();
    }

    @Test
    void pendingDeleteStatus_flaggedCritical() {
        List<RawFinding> findings =
                WhoisDecisionLogic.decide("example.com", fieldsWithStatus(List.of("pendingDelete")), NOW);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("WHOIS_DOMAIN_PENDING_DELETE");
            assertThat(f.severity().name()).isEqualTo("CRITICAL");
        });
    }

    @Test
    void redemptionPeriodStatus_flaggedCritical() {
        List<RawFinding> findings =
                WhoisDecisionLogic.decide("example.com", fieldsWithStatus(List.of("redemptionPeriod")), NOW);
        assertThat(findings).anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("WHOIS_DOMAIN_PENDING_DELETE"));
    }

    @Test
    void pendingDeleteCaseAndSpacingInsensitive_stillFlagged() {
        assertThat(WhoisDecisionLogic.decide("example.com", fieldsWithStatus(List.of("pending delete")), NOW))
                .anySatisfy(f -> assertThat(f.ruleId()).isEqualTo("WHOIS_DOMAIN_PENDING_DELETE"));
    }

    @Test
    void activeStatus_notFlaggedAsPendingDelete() {
        assertThat(WhoisDecisionLogic.decide("example.com", fieldsWithStatus(List.of("active")), NOW))
                .extracting(RawFinding::ruleId)
                .doesNotContain("WHOIS_DOMAIN_PENDING_DELETE");
    }

    @Test
    void bothExpiryApproachingAndNoTransferLock_bothFindingsFire() {
        WhoisFields fields = new WhoisFields(
                "Some Registrar", NOW.minus(1000, ChronoUnit.DAYS), NOW.plus(10, ChronoUnit.DAYS), null, List.of(),
                Map.of(), false, List.of("active"));
        List<RawFinding> findings = WhoisDecisionLogic.decide("example.com", fields, NOW);
        assertThat(findings).extracting(RawFinding::ruleId)
                .containsExactlyInAnyOrder("WHOIS_EXPIRY_APPROACHING", "WHOIS_NO_TRANSFER_LOCK");
    }
}
