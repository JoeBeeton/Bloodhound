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
        return new WhoisFields("Some Registrar", NOW.minus(1000, ChronoUnit.DAYS), expiry, null, List.of(), Map.of(), false);
    }

    @Test
    void noExpiryDate_noFindings() {
        WhoisFields fields = new WhoisFields(null, null, null, null, List.of(), Map.of(), false);
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
}
