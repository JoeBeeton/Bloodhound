package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.math.MathContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.server.findings.Finding;

/**
 * "How much would the score improve if this finding were remediated?" - per finding,
 * keyed by finding id.
 *
 * <p>Computed WITHOUT re-running {@link ScoringEngine#compute} once per finding (an
 * O(n) computation invoked n times is O(n²) in the target's total open-finding count -
 * confirmed live as a real, measured problem: a target with ~880 open findings took a
 * single dashboard load from ~250ms to 15+ seconds, computing full-recompute impact for
 * all 880 to ever display 3 of them). Instead, this exploits the specific structure of
 * the {@code 0.7^n} diminishing-returns discount directly:
 *
 * <ol>
 *   <li>Within one (category, severity) group, ranked by rule-weight descending (see
 *       {@link ScoringEngine#ranked}), removing the finding at rank {@code i} shifts
 *       every finding at rank {@code > i} down by exactly one rank. Since each
 *       contribution is {@code severityPoints * weight * 0.7^rank}, shifting from rank
 *       {@code n} to {@code n-1} means every survivor's contribution is divided by
 *       exactly {@code 0.7} - the same factor for all of them, regardless of weight.
 *       So "the new sum of everyone after rank i" is just "the old sum of everyone
 *       after rank i, divided by 0.7" - no need to touch any individual survivor.</li>
 *   <li>Everyone at rank {@code < i} is completely unaffected (still at their original
 *       rank), so their contribution total carries over unchanged.</li>
 *   <li>A category's other severity groups, and every other category entirely, are
 *       provably unaffected ({@code scoreCategory} only ever looks at findings matching
 *       its own category) - {@link ScoringEngine#overallFromCategoryScores} reuses the
 *       baseline's other 5 category scores unchanged and substitutes only the one that
 *       actually moved.</li>
 * </ol>
 *
 * <p>Net effect: one O(n log n) pass (group + sort + suffix-sum each (category,
 * severity) group once) computes everything needed to answer "what if finding X were
 * removed" for every finding in O(1) each afterward - O(n log n) total instead of O(n²).
 * Cross-checked in {@link ScoreImpactCalculatorTest} against the original O(n²)
 * brute-force approach across randomized inputs, not just the hand-derived formula.
 *
 * <p>One legitimate, provably-safe short-circuit: a finding whose category has no slot
 * in {@link ScoringEngine#CATEGORY_WEIGHTS} (WHOIS, BREACH, BRAND, COMPOUND) cannot affect
 * any category score no matter what else is in the findings list, since {@code scoreCategory}
 * only ever looks at findings matching its own category - removing it is skipped entirely
 * rather than paying for a no-op recomputation. WEB_APP is NOT in this set - it carries real
 * weight (15%, see CATEGORY_WEIGHTS) for ZAP/Nuclei findings.
 */
public final class ScoreImpactCalculator {

    /**
     * Precision for the "divide by 0.7" rank-shift step, which is otherwise a
     * non-terminating repeating decimal under exact BigDecimal arithmetic
     * (1/0.7 = 1.42857142857...). 34 significant digits is far beyond what
     * could ever be observable after the final result is rounded to 2 decimal
     * places - verified empirically via the differential test against the
     * exact (no-intermediate-rounding) brute-force computation.
     */
    private static final MathContext SHIFT_PRECISION = MathContext.DECIMAL128;

    private ScoreImpactCalculator() {}

    public static Map<UUID, ScoreImpact> computeAll(List<Finding> openFindings, Map<String, BigDecimal> ruleWeights) {
        Set<UUID> allIds = openFindings.stream().map(Finding::id).collect(Collectors.toSet());
        return computeFor(openFindings, allIds, ruleWeights);
    }

    /** Same computation as {@link #computeAll}, restricted to a subset of {@code openFindings}' ids. */
    public static Map<UUID, ScoreImpact> computeFor(
            List<Finding> openFindings, Set<UUID> findingIdsOfInterest, Map<String, BigDecimal> ruleWeights) {
        ScoreResult baseline = ScoringEngine.compute(openFindings, ruleWeights);
        Map<UUID, ScoreImpact> impacts = new LinkedHashMap<>();

        Map<String, List<Finding>> byCategory = openFindings.stream().collect(Collectors.groupingBy(Finding::category));

        for (Map.Entry<String, List<Finding>> categoryEntry : byCategory.entrySet()) {
            String category = categoryEntry.getKey();
            if (!ScoringEngine.CATEGORY_WEIGHTS.containsKey(category)) {
                for (Finding f : categoryEntry.getValue()) {
                    if (findingIdsOfInterest.contains(f.id())) {
                        impacts.put(f.id(), ScoreImpact.notApplicable(category));
                    }
                }
                continue;
            }

            Map<String, List<Finding>> bySeverity =
                    categoryEntry.getValue().stream().collect(Collectors.groupingBy(Finding::severity));

            // One pass per (category, severity) group: rank order + suffix sums of each
            // rank's discounted contribution. suffixSum[i] = sum of contributions[i..end);
            // suffixSum[0] is the group's full (pre-clamp, pre-round) deduction total.
            record GroupData(List<Finding> ranked, List<BigDecimal> suffixSums) {}
            Map<String, GroupData> groups = new LinkedHashMap<>();
            BigDecimal categoryRawDeduction = BigDecimal.ZERO;
            for (Map.Entry<String, List<Finding>> severityEntry : bySeverity.entrySet()) {
                List<Finding> ranked = ScoringEngine.ranked(severityEntry.getValue(), ruleWeights);
                List<BigDecimal> contributions =
                        ScoringEngine.contributionsForRanked(ranked, severityEntry.getKey(), ruleWeights);
                List<BigDecimal> suffixSums = new ArrayList<>(ranked.size() + 1);
                for (int i = 0; i <= ranked.size(); i++) {
                    suffixSums.add(BigDecimal.ZERO);
                }
                for (int i = ranked.size() - 1; i >= 0; i--) {
                    suffixSums.set(i, suffixSums.get(i + 1).add(contributions.get(i)));
                }
                categoryRawDeduction = categoryRawDeduction.add(suffixSums.get(0));
                groups.put(severityEntry.getKey(), new GroupData(ranked, suffixSums));
            }

            for (Map.Entry<String, GroupData> severityEntry : groups.entrySet()) {
                GroupData data = severityEntry.getValue();
                for (int i = 0; i < data.ranked().size(); i++) {
                    Finding finding = data.ranked().get(i);
                    if (!findingIdsOfInterest.contains(finding.id())) {
                        continue;
                    }

                    BigDecimal oldGroupTotal = data.suffixSums().get(0);
                    BigDecimal unaffectedPrefix = oldGroupTotal.subtract(data.suffixSums().get(i));
                    BigDecimal survivorsAfter = data.suffixSums().get(i + 1);
                    BigDecimal shiftedSurvivors = survivorsAfter.divide(ScoringEngine.DIMINISHING_FACTOR, SHIFT_PRECISION);
                    BigDecimal newGroupTotal = unaffectedPrefix.add(shiftedSurvivors);

                    BigDecimal newCategoryDeduction = categoryRawDeduction.subtract(oldGroupTotal).add(newGroupTotal);
                    BigDecimal newCategoryScore =
                            ScoringEngine.clampAndRound(ScoringEngine.ONE_HUNDRED.subtract(newCategoryDeduction));

                    Map<String, BigDecimal> hypotheticalCategoryScores = new LinkedHashMap<>(baseline.categoryScores());
                    hypotheticalCategoryScores.put(category, newCategoryScore);
                    BigDecimal hypotheticalOverall = ScoringEngine.overallFromCategoryScores(hypotheticalCategoryScores);

                    BigDecimal before = baseline.categoryScores().get(category);
                    BigDecimal overallDelta = hypotheticalOverall.subtract(baseline.overallScore());
                    impacts.put(finding.id(), new ScoreImpact(true, category, before, newCategoryScore, overallDelta));
                }
            }
        }

        return impacts;
    }
}
