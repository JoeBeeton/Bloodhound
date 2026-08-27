package org.freedonia.bloodhound.server.scoring;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.junit.jupiter.api.Test;

class ScoreImpactCalculatorTest {

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
    void singleCriticalInOneCategory_removingItRestoresCategoryTo100_overallDeltaMatchesCategoryWeight() {
        // Baseline: TLS = 100 - 40 (CRITICAL, weight 1.0, n=0) = 60.00; overall = 60*0.20 + 100*0.80 = 92.00.
        // Remove it: TLS -> 100.00 (empty), overall -> 100.00. Delta = 100.00 - 92.00 = 8.00, matching TLS's 0.20 weight.
        Finding critical = finding("SOME_RULE", "CRITICAL", "TLS");
        List<Finding> findings = List.of(critical);

        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeAll(findings, Map.of());
        ScoreImpact impact = impacts.get(critical.id());

        assertThat(impact.affectsScore()).isTrue();
        assertThat(impact.category()).isEqualTo("TLS");
        assertThat(impact.categoryScoreBefore()).isEqualByComparingTo("60.00");
        assertThat(impact.categoryScoreAfter()).isEqualByComparingTo("100.00");
        assertThat(impact.overallScoreDelta()).isEqualByComparingTo("8.00");
    }

    @Test
    void unscoredCategory_whoisFinding_notApplicable_noRecomputationNeeded() {
        Finding whoisFinding = finding("WHOIS_EXPIRY_APPROACHING", "CRITICAL", "WHOIS");
        List<Finding> findings = List.of(whoisFinding, finding("R2", "HIGH", "DNS"));

        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeAll(findings, Map.of());
        ScoreImpact impact = impacts.get(whoisFinding.id());

        assertThat(impact.affectsScore()).isFalse();
        assertThat(impact.category()).isEqualTo("WHOIS");
        assertThat(impact.categoryScoreBefore()).isNull();
        assertThat(impact.categoryScoreAfter()).isNull();
        assertThat(impact.overallScoreDelta()).isNull();
    }

    @Test
    void webAppCategory_zapFinding_alsoNotApplicable() {
        Finding zapFinding = finding("ZAP_ALERT_10202", "MEDIUM", "WEB_APP");

        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeAll(List.of(zapFinding), Map.of());

        assertThat(impacts.get(zapFinding.id()).affectsScore()).isFalse();
    }

    @Test
    void diminishingReturns_rankShift_removingFirstVsThirdHighYieldsDifferentDeltas() {
        // Three HIGHs (20pts each) in DNS, distinct rule weights so removal order is
        // deterministic (ScoringEngine breaks discount-rank ties by descending weight,
        // then ruleId) and each position's contribution is unambiguous:
        //   n=0 (RULE_HIGH, weight 3.0): 20 * 3.0 * 0.7^0 = 60.0
        //   n=1 (RULE_MED,  weight 2.0): 20 * 2.0 * 0.7^1 = 28.0
        //   n=2 (RULE_LOW,  weight 1.0): 20 * 1.0 * 0.7^2 =  9.8
        // Baseline DNS = 100 - (60.0 + 28.0 + 9.8) = 2.20; overall = 2.20*0.20 + 100*0.80 = 80.44.
        Finding highWeight = finding("RULE_HIGH", "HIGH", "DNS");
        Finding medWeight = finding("RULE_MED", "HIGH", "DNS");
        Finding lowWeight = finding("RULE_LOW", "HIGH", "DNS");
        List<Finding> findings = List.of(highWeight, medWeight, lowWeight);
        Map<String, BigDecimal> weights = Map.of(
                "RULE_HIGH", new BigDecimal("3.0"),
                "RULE_MED", new BigDecimal("2.0"),
                "RULE_LOW", new BigDecimal("1.0"));

        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeAll(findings, weights);

        // Remove RULE_HIGH (rank 0, weight 3.0): survivors RULE_MED/RULE_LOW re-rank to n=0,1:
        //   RULE_MED: 20*2.0*0.7^0 = 40.0; RULE_LOW: 20*1.0*0.7^1 = 14.0 -> total 54.0 -> DNS = 46.00
        //   overall = 46.00*0.20 + 80.00 = 89.20; delta = 89.20 - 80.44 = 8.76
        assertThat(impacts.get(highWeight.id()).categoryScoreAfter()).isEqualByComparingTo("46.00");
        assertThat(impacts.get(highWeight.id()).overallScoreDelta()).isEqualByComparingTo("8.76");

        // Remove RULE_LOW (rank 2, weight 1.0): survivors RULE_HIGH/RULE_MED keep ranks n=0,1
        //   (already the two highest-weighted, so removing the 3rd-ranked one doesn't reshuffle them):
        //   RULE_HIGH: 60.0 (unchanged); RULE_MED: 28.0 (unchanged) -> total 88.0 -> DNS = 12.00
        //   overall = 12.00*0.20 + 80.00 = 82.40; delta = 82.40 - 80.44 = 1.96
        assertThat(impacts.get(lowWeight.id()).categoryScoreAfter()).isEqualByComparingTo("12.00");
        assertThat(impacts.get(lowWeight.id()).overallScoreDelta()).isEqualByComparingTo("1.96");

        // The two deltas are genuinely different (8.76 vs 1.96) - proof the calculator
        // isn't using a flat "just undo this one finding's own deduction" shortcut, since
        // that would have wrongly produced the *same* per-finding delta regardless of which
        // of the three findings was removed.
        assertThat(impacts.get(highWeight.id()).overallScoreDelta())
                .isNotEqualByComparingTo(impacts.get(lowWeight.id()).overallScoreDelta());
    }

    @Test
    void multipleFindingsAcrossCategories_eachImpactComputedIndependently() {
        Finding tlsFinding = finding("R_TLS", "HIGH", "TLS");
        Finding dnsFinding = finding("R_DNS", "MEDIUM", "DNS");
        List<Finding> findings = List.of(tlsFinding, dnsFinding);

        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeAll(findings, Map.of());

        // TLS alone: 100 - 20 = 80.00 (weight 0.20) -> removing it recovers 20*0.20 = 4.00 overall.
        assertThat(impacts.get(tlsFinding.id()).category()).isEqualTo("TLS");
        assertThat(impacts.get(tlsFinding.id()).overallScoreDelta()).isEqualByComparingTo("4.00");
        // DNS alone: 100 - 10 = 90.00 (weight 0.20) -> removing it recovers 10*0.20 = 2.00 overall.
        assertThat(impacts.get(dnsFinding.id()).category()).isEqualTo("DNS");
        assertThat(impacts.get(dnsFinding.id()).overallScoreDelta()).isEqualByComparingTo("2.00");
    }

    @Test
    void computeFor_subsetOfIds_onlyReturnsImpactsForThoseIds() {
        Finding tlsFinding = finding("R_TLS", "HIGH", "TLS");
        Finding dnsFinding = finding("R_DNS", "MEDIUM", "DNS");
        List<Finding> findings = List.of(tlsFinding, dnsFinding);

        Map<UUID, ScoreImpact> impacts =
                ScoreImpactCalculator.computeFor(findings, Set.of(tlsFinding.id()), Map.of());

        assertThat(impacts).containsOnlyKeys(tlsFinding.id());
    }

    @Test
    void computeFor_subsetResult_matchesWhatComputeAllWouldHaveReturnedForThatId() {
        // The full-set baseline (and therefore every "before" score and every other
        // finding's "without" hypothetical) must still reflect ALL open findings, not just
        // the ones being computed for - computeFor must not silently narrow the context.
        Finding highWeight = finding("RULE_HIGH", "HIGH", "DNS");
        Finding medWeight = finding("RULE_MED", "HIGH", "DNS");
        Finding lowWeight = finding("RULE_LOW", "HIGH", "DNS");
        List<Finding> findings = List.of(highWeight, medWeight, lowWeight);
        Map<String, BigDecimal> weights = Map.of(
                "RULE_HIGH", new BigDecimal("3.0"),
                "RULE_MED", new BigDecimal("2.0"),
                "RULE_LOW", new BigDecimal("1.0"));

        Map<UUID, ScoreImpact> full = ScoreImpactCalculator.computeAll(findings, weights);
        Map<UUID, ScoreImpact> subset =
                ScoreImpactCalculator.computeFor(findings, Set.of(lowWeight.id()), weights);

        assertThat(subset).containsOnlyKeys(lowWeight.id());
        assertThat(subset.get(lowWeight.id()).categoryScoreAfter())
                .isEqualByComparingTo(full.get(lowWeight.id()).categoryScoreAfter());
        assertThat(subset.get(lowWeight.id()).overallScoreDelta())
                .isEqualByComparingTo(full.get(lowWeight.id()).overallScoreDelta());
    }

    @Test
    void computeFor_emptySubset_emptyResult() {
        Finding finding = finding("R1", "HIGH", "TLS");
        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeFor(List.of(finding), Set.of(), Map.of());
        assertThat(impacts).isEmpty();
    }

    @Test
    void computeFor_idNotInOpenFindings_simplyIgnored() {
        Finding finding = finding("R1", "HIGH", "TLS");
        Map<UUID, ScoreImpact> impacts =
                ScoreImpactCalculator.computeFor(List.of(finding), Set.of(UUID.randomUUID()), Map.of());
        assertThat(impacts).isEmpty();
    }

    /**
     * Regression test for a real production hang: a single (category, severity) group with
     * tens of thousands of findings (confirmed live - one real target had 36,466 open findings,
     * the bulk of them the same LOW/EXPOSURE combination) made {@code 0.7^n} for n in the tens
     * of thousands - computed via {@link BigDecimal#pow(int)} with no precision bound, i.e.
     * EXACTLY, meaning a BigDecimal with n digits of scale - so expensive that summing tens of
     * thousands of them never finished inside a 2-minute request timeout. Must stay fast
     * (asserted via a generous-but-real wall-clock bound, not just "doesn't throw") and must
     * still be numerically correct for the findings actually examined.
     */
    @Test
    void largeSingleGroup_manyThousandsOfFindingsSameCategoryAndSeverity_staysFastAndCorrect() {
        List<Finding> findings = new java.util.ArrayList<>();
        for (int i = 0; i < 40_000; i++) {
            findings.add(finding("RULE_" + i, "LOW", "EXPOSURE"));
        }
        UUID firstRankId = findings.get(0).id();

        long start = System.nanoTime();
        Map<UUID, ScoreImpact> impacts = ScoreImpactCalculator.computeFor(findings, Set.of(firstRankId), Map.of());
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertThat(elapsedMs)
                .as("computeFor on a 40,000-finding single group took %d ms - should be near-instant", elapsedMs)
                .isLessThan(5_000);
        // With 40,000 findings in the group - far more than the ~130-rank point where 0.7^n
        // rounds to zero - the group's deduction is effectively an infinite converged geometric
        // series (4 * 1/(1-0.7) = 13.33...). Removing the single top-ranked finding shifts
        // every survivor's rank down by one (dividing the tail by 0.7), which for a converged
        // series leaves the sum unchanged at 2-decimal precision: correctly reflects that in a
        // category already saturated with tens of thousands of low-severity issues, fixing any
        // one of them makes no practically visible difference to the score.
        ScoreImpact impact = impacts.get(firstRankId);
        assertThat(impact.affectsScore()).isTrue();
        assertThat(impact.category()).isEqualTo("EXPOSURE");
        assertThat(impact.categoryScoreBefore()).isEqualByComparingTo(new BigDecimal("86.67"));
        assertThat(impact.categoryScoreAfter()).isEqualByComparingTo(new BigDecimal("86.67"));
        assertThat(impact.overallScoreDelta()).isEqualByComparingTo(BigDecimal.ZERO);
    }
}
