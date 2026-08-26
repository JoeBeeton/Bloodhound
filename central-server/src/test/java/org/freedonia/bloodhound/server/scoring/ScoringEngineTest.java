package org.freedonia.bloodhound.server.scoring;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.junit.jupiter.api.Test;

class ScoringEngineTest {

    private static Finding finding(String ruleId, String severity, String category) {
        UUID run = UUID.randomUUID();
        return new Finding(
                UUID.randomUUID(),
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

    @Test
    void emptyFindings_allCategoriesAndOverallAre100_gradeA() {
        ScoreResult result = ScoringEngine.compute(List.of(), Map.of());

        assertThat(result.categoryScores().values()).allSatisfy(score -> assertThat(score).isEqualByComparingTo("100"));
        assertThat(result.overallScore()).isEqualByComparingTo("100.00");
        assertThat(result.grade()).isEqualTo("A");
    }

    @Test
    void singleCriticalInOneCategory_deductsExactlyExpectedAmount_othersUnaffected() {
        // CRITICAL=40 points * weight 1.0 (no catalog entry -> default) * 0.7^0 (first in its group) = 40
        // category score = 100 - 40 = 60
        List<Finding> findings = List.of(finding("SOME_RULE", "CRITICAL", "TLS"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.categoryScores().get("TLS")).isEqualByComparingTo("60.00");
        assertThat(result.categoryScores().get("DNS")).isEqualByComparingTo("100.00");
        assertThat(result.categoryScores().get("HEADERS")).isEqualByComparingTo("100.00");
        assertThat(result.categoryScores().get("NETWORK")).isEqualByComparingTo("100.00");
        assertThat(result.categoryScores().get("EXPOSURE")).isEqualByComparingTo("100.00");
        assertThat(result.categoryScores().get("SUBDOMAIN_HYGIENE")).isEqualByComparingTo("100.00");
    }

    @Test
    void diminishingReturns_threeHighsInSameCategory_matchesHandCalculatedCurve() {
        // HIGH=20 points, weight 1.0 each (no catalog entries, all default).
        // n=0: 20 * 1 * 0.7^0 = 20.0
        // n=1: 20 * 1 * 0.7^1 = 14.0
        // n=2: 20 * 1 * 0.7^2 =  9.8
        // total deduction = 43.8 -> category score = 100 - 43.8 = 56.2
        List<Finding> findings = List.of(
                finding("RULE_A", "HIGH", "DNS"), finding("RULE_B", "HIGH", "DNS"), finding("RULE_C", "HIGH", "DNS"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.categoryScores().get("DNS")).isEqualByComparingTo("56.20");
    }

    @Test
    void twoCriticalsInDifferentCategories_eachScoredIndependentlyAtFullWeight() {
        // Diminishing returns is scoped per-category: a Critical in TLS and a
        // Critical in DNS are each the "0th" finding of their own group, so
        // both take the full, undiscounted 40-point deduction.
        List<Finding> findings = List.of(finding("RULE_A", "CRITICAL", "TLS"), finding("RULE_B", "CRITICAL", "DNS"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.categoryScores().get("TLS")).isEqualByComparingTo("60.00");
        assertThat(result.categoryScores().get("DNS")).isEqualByComparingTo("60.00");
    }

    @Test
    void ruleWeightOverride_scalesDeductionProportionally() {
        // MEDIUM=10 points. Rule A at weight 1.0 -> 10 * 1.0 = 10 deduction -> score 90.
        // Rule B at weight 1.5 -> 10 * 1.5 = 15 deduction -> score 85.
        // Each is the sole finding in its own category, so no diminishing-returns interaction.
        List<Finding> baseline = List.of(finding("RULE_A", "MEDIUM", "HEADERS"));
        List<Finding> weighted = List.of(finding("RULE_B", "MEDIUM", "NETWORK"));
        Map<String, BigDecimal> weights = Map.of("RULE_A", new BigDecimal("1.0"), "RULE_B", new BigDecimal("1.5"));

        ScoreResult baselineResult = ScoringEngine.compute(baseline, weights);
        ScoreResult weightedResult = ScoringEngine.compute(weighted, weights);

        assertThat(baselineResult.categoryScores().get("HEADERS")).isEqualByComparingTo("90.00");
        assertThat(weightedResult.categoryScores().get("NETWORK")).isEqualByComparingTo("85.00");
    }

    @Test
    void missingRuleWeightLookup_defaultsToOnePointZero_doesNotThrow() {
        List<Finding> findings = List.of(finding("RULE_NOT_IN_CATALOG", "MEDIUM", "HEADERS"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of("SOME_OTHER_RULE", new BigDecimal("2.0")));

        // 10 * 1.0 (default weight) = 10 deduction -> 90, not 80 (which would imply the 2.0 weight leaked in).
        assertThat(result.categoryScores().get("HEADERS")).isEqualByComparingTo("90.00");
    }

    @Test
    void gradeBoundaries_useGreaterThanOrEqualSemantics() {
        assertThat(gradeForOverall("90.00")).isEqualTo("A");
        assertThat(gradeForOverall("89.99")).isEqualTo("B");
        assertThat(gradeForOverall("80.00")).isEqualTo("B");
        assertThat(gradeForOverall("79.99")).isEqualTo("C");
        assertThat(gradeForOverall("70.00")).isEqualTo("C");
        assertThat(gradeForOverall("69.99")).isEqualTo("D");
        assertThat(gradeForOverall("60.00")).isEqualTo("D");
        assertThat(gradeForOverall("59.99")).isEqualTo("F");
    }

    /**
     * Drives the engine to an exact overall score by deducting the same
     * amount `d` from every one of the 6 categories: since the category
     * weights sum to exactly 1.00 (0.25+0.20+0.20+0.15+0.10+0.10), a uniform
     * per-category deduction of `d` yields overall = 100 - d regardless of
     * individual category weights, which is far simpler to hit exactly than
     * solving through a single category (whose weight caps how far overall
     * can move using only that category, and can require a negative,
     * unreachable-after-clamping category score for low targets).
     * Each category gets exactly one HIGH (20pt) finding as the sole/0th
     * finding in its group, so no diminishing-returns discount applies and
     * deduction = 20 * weight = d exactly.
     */
    private static String gradeForOverall(String targetOverall) {
        BigDecimal deduction = new BigDecimal("100").subtract(new BigDecimal(targetOverall));
        BigDecimal weight = deduction.divide(new BigDecimal("20"));
        List<String> categories =
                List.of("EXPOSURE", "TLS", "DNS", "NETWORK", "HEADERS", "SUBDOMAIN_HYGIENE");
        List<Finding> findings = categories.stream()
                .map(category -> finding("BOUNDARY_RULE_" + category, "HIGH", category))
                .toList();
        Map<String, BigDecimal> weights =
                categories.stream().collect(java.util.stream.Collectors.toMap(c -> "BOUNDARY_RULE_" + c, c -> weight));

        ScoreResult result = ScoringEngine.compute(findings, weights);
        assertThat(result.overallScore()).isEqualByComparingTo(targetOverall);
        return result.grade();
    }

    @Test
    void overallScoreWeighting_matchesFixedCategoryWeightTable() {
        // One finding per category, each driven to a distinct, easily-hand-checked score via a tailored weight.
        // TLS -> 80 (20 deducted), DNS -> 70 (30 deducted), HEADERS -> 60 (40 deducted),
        // NETWORK -> 90 (10 deducted), EXPOSURE -> 100 (no finding), SUBDOMAIN_HYGIENE -> 100 (no finding).
        List<Finding> findings = List.of(
                finding("R_TLS", "HIGH", "TLS"), // 20 * weight1.0 = 20 -> 80
                finding("R_DNS", "HIGH", "DNS"), // 20 * weight1.5 = 30 -> 70
                finding("R_HEADERS", "HIGH", "HEADERS"), // 20 * weight2.0 = 40 -> 60
                finding("R_NETWORK", "HIGH", "NETWORK") // 20 * weight0.5 = 10 -> 90
                );
        Map<String, BigDecimal> weights = Map.of(
                "R_TLS", new BigDecimal("1.0"),
                "R_DNS", new BigDecimal("1.5"),
                "R_HEADERS", new BigDecimal("2.0"),
                "R_NETWORK", new BigDecimal("0.5"));

        ScoreResult result = ScoringEngine.compute(findings, weights);

        // overall = 80*0.20 + 70*0.20 + 60*0.10 + 90*0.15 + 100*0.25 + 100*0.10
        //         = 16 + 14 + 6 + 13.5 + 25 + 10 = 84.5
        assertThat(result.overallScore()).isEqualByComparingTo("84.50");
        assertThat(result.grade()).isEqualTo("B");
    }

    @Test
    void categoriesWithNoScanModuleYet_exposureAndNetworkDefaultTo100() {
        // As of Milestone 5, EXPOSURE and NETWORK have no scan module producing findings for them.
        // The fixed 6-category weight table must not need to change when Milestone 6 adds real
        // findings there - zero open findings in a category should just fall out to 100 via the
        // same general per-category logic, with no special-casing.
        List<Finding> findings =
                List.of(finding("R1", "HIGH", "DNS"), finding("R2", "MEDIUM", "HEADERS"), finding("R3", "LOW", "TLS"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.categoryScores().get("EXPOSURE")).isEqualByComparingTo("100.00");
        assertThat(result.categoryScores().get("NETWORK")).isEqualByComparingTo("100.00");
    }

    @Test
    void scoreClamping_heavyDeductionsClampToExactlyZero_neverNegative() {
        // Five CRITICALs in one category: even fully discounted, 40*(1+0.7+0.49+0.343+0.2401) = 40*2.7531 = 110.124,
        // which already exceeds 100 before the 5th term - deduction overshoots 100, must clamp to 0, not go negative.
        List<Finding> findings = List.of(
                finding("R1", "CRITICAL", "EXPOSURE"),
                finding("R2", "CRITICAL", "EXPOSURE"),
                finding("R3", "CRITICAL", "EXPOSURE"),
                finding("R4", "CRITICAL", "EXPOSURE"),
                finding("R5", "CRITICAL", "EXPOSURE"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.categoryScores().get("EXPOSURE")).isEqualByComparingTo("0.00");
    }

    @Test
    void findingCounts_tallySeverityAcrossAllCategories() {
        List<Finding> findings = List.of(
                finding("R1", "CRITICAL", "TLS"),
                finding("R2", "HIGH", "DNS"),
                finding("R3", "HIGH", "HEADERS"),
                finding("R4", "INFO", "SUBDOMAIN_HYGIENE"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.findingCounts())
                .containsEntry("CRITICAL", 1L)
                .containsEntry("HIGH", 2L)
                .containsEntry("MEDIUM", 0L)
                .containsEntry("LOW", 0L)
                .containsEntry("INFO", 1L);
    }

    @Test
    void whoisCategoryFinding_excludedFromScoringEntirely_evenAtCriticalSeverity() {
        // WHOIS (Milestone 6a) is a real findings.category value with no slot in CATEGORY_WEIGHTS - it
        // should show up in the findings list/UI (via the normal findings endpoints) but never move the
        // score, exactly like a category with no scan module yet, but for a different reason (deliberately
        // excluded, not just not-yet-implemented).
        List<Finding> findings = List.of(finding("WHOIS_EXPIRY_APPROACHING", "CRITICAL", "WHOIS"));

        ScoreResult result = ScoringEngine.compute(findings, Map.of());

        assertThat(result.categoryScores()).doesNotContainKey("WHOIS");
        assertThat(result.overallScore()).isEqualByComparingTo("100.00");
        assertThat(result.grade()).isEqualTo("A");
        // Still tallied in the severity breakdown - it's a real, visible finding, just not a scored one.
        assertThat(result.findingCounts()).containsEntry("CRITICAL", 1L);
    }
}
