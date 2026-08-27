package org.freedonia.bloodhound.server.scoring;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.junit.jupiter.api.RepeatedTest;

/**
 * Cross-checks {@link ScoreImpactCalculator}'s O(n log n) suffix-sum
 * shortcut against a deliberately naive, obviously-correct O(n²)
 * brute-force reference (re-run {@link ScoringEngine#compute} with each
 * finding excluded in turn - exactly what {@code ScoreImpactCalculator}
 * itself did before this optimization) across randomized inputs. The hand-
 * derived formula is proven correct algebraically in the class javadoc, but
 * randomized differential testing catches implementation slips (off-by-one
 * in the suffix-sum indexing, precision loss in the 1/0.7 shift) that a
 * handful of hand-picked example-based tests could miss.
 */
class ScoreImpactCalculatorDifferentialTest {

    private static final List<String> CATEGORIES =
            List.of("EXPOSURE", "TLS", "DNS", "NETWORK", "HEADERS", "SUBDOMAIN_HYGIENE", "WHOIS", "WEB_APP");
    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

    private static Finding finding(String ruleId, String severity, String category) {
        UUID run = UUID.randomUUID();
        return new Finding(
                UUID.randomUUID(), "bh-test-1", run, UUID.randomUUID(), "SOME_MODULE", ruleId, severity, category, "title",
                "description", "{}", "asset", run, "OPEN", null, Instant.now(), Instant.now());
    }

    /** The original O(n²) implementation, kept here only as a reference oracle for this test. */
    private static Map<UUID, ScoreImpact> naiveComputeAll(List<Finding> openFindings, Map<String, BigDecimal> ruleWeights) {
        ScoreResult baseline = ScoringEngine.compute(openFindings, ruleWeights);
        Map<UUID, ScoreImpact> impacts = new java.util.LinkedHashMap<>();
        for (Finding finding : openFindings) {
            if (!ScoringEngine.CATEGORY_WEIGHTS.containsKey(finding.category())) {
                impacts.put(finding.id(), ScoreImpact.notApplicable(finding.category()));
                continue;
            }
            List<Finding> without = openFindings.stream().filter(f -> !f.id().equals(finding.id())).toList();
            ScoreResult hypothetical = ScoringEngine.compute(without, ruleWeights);
            BigDecimal before = baseline.categoryScores().get(finding.category());
            BigDecimal after = hypothetical.categoryScores().get(finding.category());
            BigDecimal overallDelta = hypothetical.overallScore().subtract(baseline.overallScore());
            impacts.put(finding.id(), new ScoreImpact(true, finding.category(), before, after, overallDelta));
        }
        return impacts;
    }

    @RepeatedTest(50)
    void fastImplementation_matchesNaiveBruteForce_acrossRandomFindingSets() {
        Random random = new Random();
        int findingCount = 1 + random.nextInt(60);
        List<Finding> findings = new ArrayList<>();
        Map<String, BigDecimal> ruleWeights = new java.util.HashMap<>();
        for (int i = 0; i < findingCount; i++) {
            String ruleId = "RULE_" + i;
            String severity = SEVERITIES.get(random.nextInt(SEVERITIES.size()));
            String category = CATEGORIES.get(random.nextInt(CATEGORIES.size()));
            findings.add(finding(ruleId, severity, category));
            // Weight sometimes explicitly set, sometimes left to default via absence -
            // exercises both the ruleWeights lookup hit and miss paths.
            if (random.nextBoolean()) {
                double weight = 0.1 + random.nextDouble() * 4.9;
                ruleWeights.put(ruleId, BigDecimal.valueOf(Math.round(weight * 100) / 100.0));
            }
        }

        Map<UUID, ScoreImpact> naive = naiveComputeAll(findings, ruleWeights);
        Map<UUID, ScoreImpact> fast = ScoreImpactCalculator.computeAll(findings, ruleWeights);

        assertThat(fast.keySet()).containsExactlyInAnyOrderElementsOf(naive.keySet());
        for (Finding f : findings) {
            ScoreImpact naiveImpact = naive.get(f.id());
            ScoreImpact fastImpact = fast.get(f.id());
            assertThat(fastImpact.affectsScore())
                    .as("affectsScore for finding %s (%s)", f.id(), f.category())
                    .isEqualTo(naiveImpact.affectsScore());
            if (!naiveImpact.affectsScore()) {
                assertThat(fastImpact.category()).isEqualTo(naiveImpact.category());
                continue;
            }
            assertThat(fastImpact.categoryScoreBefore())
                    .as("before, finding %s", f.id())
                    .isEqualByComparingTo(naiveImpact.categoryScoreBefore());
            assertThat(fastImpact.categoryScoreAfter())
                    .as("after, finding %s", f.id())
                    .isEqualByComparingTo(naiveImpact.categoryScoreAfter());
            assertThat(fastImpact.overallScoreDelta())
                    .as("overallDelta, finding %s", f.id())
                    .isEqualByComparingTo(naiveImpact.overallScoreDelta());
        }
    }

    @RepeatedTest(20)
    void fastImplementation_matchesNaive_manyFindingsSameCategoryAndSeverity_worstCaseForRankShifting() {
        // Deliberately concentrates everything into one (category, severity) group - the
        // scenario where every finding's removal shifts every other finding's rank, the
        // exact case the suffix-sum shortcut exists to handle correctly.
        Random random = new Random();
        int findingCount = 5 + random.nextInt(40);
        List<Finding> findings = new ArrayList<>();
        Map<String, BigDecimal> ruleWeights = new java.util.HashMap<>();
        for (int i = 0; i < findingCount; i++) {
            String ruleId = "RULE_" + i;
            findings.add(finding(ruleId, "HIGH", "DNS"));
            double weight = 0.1 + random.nextDouble() * 4.9;
            ruleWeights.put(ruleId, BigDecimal.valueOf(Math.round(weight * 100) / 100.0));
        }

        Map<UUID, ScoreImpact> naive = naiveComputeAll(findings, ruleWeights);
        Map<UUID, ScoreImpact> fast = ScoreImpactCalculator.computeAll(findings, ruleWeights);

        for (Finding f : findings) {
            assertThat(fast.get(f.id()).overallScoreDelta())
                    .as("overallDelta, finding %s", f.id())
                    .isEqualByComparingTo(naive.get(f.id()).overallScoreDelta());
        }
    }

    @RepeatedTest(10)
    void fastImplementation_matchesNaive_heavyDeductionsNearClampBoundary() {
        // Enough CRITICALs in one category to push the raw deduction well past 100 (forcing
        // the clamp-to-zero path) both at baseline and after removing one - the shortcut's
        // arithmetic happens entirely pre-clamp, so this specifically exercises whether
        // clampAndRound is applied consistently at the same point in both implementations.
        Random random = new Random();
        int findingCount = 6 + random.nextInt(10);
        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < findingCount; i++) {
            findings.add(finding("RULE_" + i, "CRITICAL", "EXPOSURE"));
        }

        Map<UUID, ScoreImpact> naive = naiveComputeAll(findings, Map.of());
        Map<UUID, ScoreImpact> fast = ScoreImpactCalculator.computeAll(findings, Map.of());

        for (Finding f : findings) {
            assertThat(fast.get(f.id()).categoryScoreAfter())
                    .as("after, finding %s", f.id())
                    .isEqualByComparingTo(naive.get(f.id()).categoryScoreAfter());
        }
    }

    @RepeatedTest(20)
    void computeFor_subsetResults_matchComputeAll_forThoseSameIds() {
        Random random = new Random();
        int findingCount = 2 + random.nextInt(30);
        List<Finding> findings = new ArrayList<>();
        Map<String, BigDecimal> ruleWeights = new java.util.HashMap<>();
        for (int i = 0; i < findingCount; i++) {
            String ruleId = "RULE_" + i;
            String severity = SEVERITIES.get(random.nextInt(SEVERITIES.size()));
            String category = CATEGORIES.get(random.nextInt(CATEGORIES.size()));
            findings.add(finding(ruleId, severity, category));
            ruleWeights.put(ruleId, BigDecimal.valueOf(0.5 + random.nextDouble() * 2));
        }

        Map<UUID, ScoreImpact> all = ScoreImpactCalculator.computeAll(findings, ruleWeights);
        // A random subset of interest, including possibly none/all.
        java.util.Set<UUID> subsetIds = findings.stream()
                .filter(f -> random.nextBoolean())
                .map(Finding::id)
                .collect(java.util.stream.Collectors.toSet());
        Map<UUID, ScoreImpact> subset = ScoreImpactCalculator.computeFor(findings, subsetIds, ruleWeights);

        assertThat(subset.keySet()).containsExactlyInAnyOrderElementsOf(subsetIds);
        for (UUID id : subsetIds) {
            ScoreImpact expected = all.get(id);
            ScoreImpact actual = subset.get(id);
            assertThat(actual.affectsScore()).isEqualTo(expected.affectsScore());
            if (expected.affectsScore()) {
                assertThat(actual.overallScoreDelta()).isEqualByComparingTo(expected.overallScoreDelta());
            }
        }
    }
}
