package org.freedonia.bloodhound.server.scoring;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.junit.jupiter.api.Test;

/**
 * Proves the Tier-1-only "fair comparison" score computation - the same
 * filter-then-{@link ScoringEngine#compute} logic {@link ScoreSnapshotService}
 * runs against the DB, exercised here as a pure computation so it's testable
 * without Spring/Postgres. The correctness trap this guards against:
 * PORT_UNEXPECTED_OPEN_ADMIN_SERVICE/PORT_OPEN_UNENCRYPTED_MGMT are shared
 * rule_ids a Tier 1 light scan is equally capable of finding on its own, so
 * they must NOT be excluded from the Tier-1-only score - only genuinely
 * Tier-2-exclusive rule_ids (NETWORK_ANONYMOUS_FTP, NETWORK_FULL_PORT_SURFACE)
 * should be.
 */
class Tier1OnlyScoringTest {

    private static final Set<String> TIER2_EXCLUSIVE = Set.of("NETWORK_ANONYMOUS_FTP", "NETWORK_FULL_PORT_SURFACE");

    private static Finding finding(String ruleId, String severity, String category) {
        UUID run = UUID.randomUUID();
        return new Finding(
                UUID.randomUUID(),
                "bh-test-1",
                run,
                UUID.randomUUID(),
                "SOME_MODULE",
                ruleId,
                severity,
                category,
                "title",
                "description",
                "{}",
                "asset",
                run,
                "OPEN",
                null,
                Instant.now(),
                Instant.now());
    }

    private static ScoreResult tier1Only(List<Finding> openFindings) {
        List<Finding> tier1Findings = openFindings.stream()
                .filter(f -> !TIER2_EXCLUSIVE.contains(f.ruleId()))
                .filter(f -> !"WEB_APP".equals(f.category()))
                .toList();
        return ScoringEngine.compute(tier1Findings, Map.of());
    }

    @Test
    void tier2ExclusiveFinding_excludedFromTier1Score_butIncludedInFullScore() {
        // NETWORK_ANONYMOUS_FTP: CRITICAL=40 * weight 1.0 * 0.7^0 = 40 deduction -> NETWORK category = 60
        List<Finding> findings = List.of(finding("NETWORK_ANONYMOUS_FTP", "CRITICAL", "NETWORK"));

        ScoreResult full = ScoringEngine.compute(findings, Map.of());
        ScoreResult tier1 = tier1Only(findings);

        assertThat(full.categoryScores().get("NETWORK")).isEqualByComparingTo("60.00");
        assertThat(tier1.categoryScores().get("NETWORK")).isEqualByComparingTo("100.00");
        assertThat(full.overallScore()).isNotEqualByComparingTo(tier1.overallScore());
        assertThat(tier1.overallScore()).isGreaterThan(full.overallScore());
    }

    @Test
    void sharedRuleId_reusedByDeepScan_stillCountsTowardTier1Score() {
        // PORT_UNEXPECTED_OPEN_ADMIN_SERVICE can come from either PORT_SCAN_LIGHT (Tier 1) or
        // PORT_SCAN_DEEP (Tier 2, same rule_id with richer evidence) - a Tier 1 light scan is
        // equally capable of finding this port open on its own, so it must count toward BOTH
        // scores identically, regardless of which module most recently touched the finding row.
        List<Finding> findings = List.of(finding("PORT_UNEXPECTED_OPEN_ADMIN_SERVICE", "HIGH", "NETWORK"));

        ScoreResult full = ScoringEngine.compute(findings, Map.of());
        ScoreResult tier1 = tier1Only(findings);

        assertThat(full.overallScore()).isEqualByComparingTo(tier1.overallScore());
        assertThat(full.categoryScores().get("NETWORK")).isEqualByComparingTo(tier1.categoryScores().get("NETWORK"));
    }

    @Test
    void mixOfTier1EligibleAndTier2Exclusive_onlyExclusiveOnesDropped() {
        List<Finding> findings = List.of(
                finding("DNS_SPF_MISSING", "HIGH", "DNS"), // tier1-eligible
                finding("NETWORK_FULL_PORT_SURFACE", "INFO", "NETWORK"), // tier2-exclusive, INFO = 0 pts anyway
                finding("NETWORK_ANONYMOUS_FTP", "CRITICAL", "NETWORK") // tier2-exclusive, real deduction
                );

        ScoreResult full = ScoringEngine.compute(findings, Map.of());
        ScoreResult tier1 = tier1Only(findings);

        // DNS category identical in both (its only finding is tier1-eligible)
        assertThat(full.categoryScores().get("DNS")).isEqualByComparingTo(tier1.categoryScores().get("DNS"));
        assertThat(full.categoryScores().get("DNS")).isEqualByComparingTo("80.00"); // 100 - 20 (HIGH)

        // NETWORK differs: full has the CRITICAL FTP deduction, tier1 has neither tier2-exclusive finding
        assertThat(full.categoryScores().get("NETWORK")).isEqualByComparingTo("60.00");
        assertThat(tier1.categoryScores().get("NETWORK")).isEqualByComparingTo("100.00");

        assertThat(tier1.overallScore()).isGreaterThan(full.overallScore());
    }

    @Test
    void webAppFinding_zapOrNucleiActiveScanResult_alwaysExcludedFromTier1Score() {
        // ZAP/Nuclei are exclusively Tier 2 modules (see ZapAlertMapper/NucleiFindingMapper) -
        // WEB_APP carries no rules_catalog rows at all (their rule_ids are dynamically generated
        // per plugin/template), so unlike NETWORK_ANONYMOUS_FTP/NETWORK_FULL_PORT_SURFACE this
        // can't be excluded via the ruleId-based TIER2_EXCLUSIVE set above - it's excluded by
        // category instead, since Tier 1 never produces a WEB_APP finding at all. Real gap found
        // live: before this exclusion existed, WEB_APP had no weight in ScoringEngine at all, so
        // there was nothing to exclude and full/tier1 scores looked identical for every target -
        // not because the split was working, but because it had nothing real to do.
        List<Finding> findings = List.of(finding("ZAP_ALERT_40012", "CRITICAL", "WEB_APP"));

        ScoreResult full = ScoringEngine.compute(findings, Map.of());
        ScoreResult tier1 = tier1Only(findings);

        assertThat(full.categoryScores().get("WEB_APP")).isEqualByComparingTo("60.00");
        assertThat(tier1.categoryScores().get("WEB_APP")).isEqualByComparingTo("100.00");
        assertThat(tier1.overallScore()).isGreaterThan(full.overallScore());
    }

    @Test
    void noTier2ExclusiveFindings_fullAndTier1ScoresIdentical() {
        // A competitor target scanned Tier 1 only never has Tier 2-exclusive findings to begin
        // with, so both scores must come out identical - this is the expected, correct outcome
        // for any target that's never been deep-scanned, not a bug.
        List<Finding> findings = List.of(
                finding("DNS_SPF_MISSING", "HIGH", "DNS"), finding("HEADER_CSP_MISSING", "MEDIUM", "HEADERS"));

        ScoreResult full = ScoringEngine.compute(findings, Map.of());
        ScoreResult tier1 = tier1Only(findings);

        assertThat(full.overallScore()).isEqualByComparingTo(tier1.overallScore());
        assertThat(full.grade()).isEqualTo(tier1.grade());
        assertThat(full.categoryScores()).isEqualTo(tier1.categoryScores());
    }
}
