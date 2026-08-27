package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.server.findings.Finding;

/**
 * Pure scoring computation: a list of currently-OPEN findings + a rule-id ->
 * weight lookup in, a {@link ScoreResult} out. No DB access here - that's
 * {@link ScoreSnapshotService}'s job, which is what makes this class
 * trivially unit-testable.
 *
 * <p>Every {@link ScoreResult} is computed fresh from the findings open
 * <i>right now</i>: there is no time-based decay or grace mechanism. A
 * finding that gets resolved simply isn't in the input list for the next
 * computation, so category scores recover immediately; a brand-new Critical
 * finding is scored at full weight immediately, since "diminishing returns"
 * below only discounts multiple findings of the same severity within the
 * same computation, never across scan runs.
 */
public final class ScoringEngine {

    /** Fixed weighting - not configurable in Phase 1. Categories with no scan module yet score 100 by falling out of the same general logic (zero open findings = zero deduction), so this table doesn't need to change as later milestones add EXPOSURE/NETWORK modules. */
    static final Map<String, BigDecimal> CATEGORY_WEIGHTS = Map.of(
            "EXPOSURE", new BigDecimal("0.25"),
            "TLS", new BigDecimal("0.20"),
            "DNS", new BigDecimal("0.20"),
            "NETWORK", new BigDecimal("0.15"),
            "HEADERS", new BigDecimal("0.10"),
            "SUBDOMAIN_HYGIENE", new BigDecimal("0.10"));

    private static final List<String> CATEGORIES = List.copyOf(CATEGORY_WEIGHTS.keySet());

    private static final Map<String, BigDecimal> SEVERITY_POINTS = Map.of(
            "CRITICAL", new BigDecimal("40"),
            "HIGH", new BigDecimal("20"),
            "MEDIUM", new BigDecimal("10"),
            "LOW", new BigDecimal("4"),
            "INFO", BigDecimal.ZERO);

    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

    /** The nth (0-indexed) finding of a given severity within one category counts at this factor to the power of n. */
    static final BigDecimal DIMINISHING_FACTOR = new BigDecimal("0.7");

    static final BigDecimal ONE_HUNDRED = new BigDecimal("100");
    static final int SCALE = 2;

    private ScoringEngine() {}

    public static ScoreResult compute(List<Finding> openFindings, Map<String, BigDecimal> ruleWeights) {
        Map<String, BigDecimal> categoryScores = new LinkedHashMap<>();
        for (String category : CATEGORIES) {
            categoryScores.put(category, scoreCategory(openFindings, category, ruleWeights));
        }

        BigDecimal overall = overallFromCategoryScores(categoryScores);
        return new ScoreResult(overall, gradeFor(overall), categoryScores, countBySeverity(openFindings));
    }

    /**
     * Package-visible so {@link ScoreImpactCalculator} can recompute just the
     * overall score after substituting one category's hypothetical score,
     * without needing to reconstruct a whole hypothetical findings list and
     * pay for a full {@link #compute} - reused rather than duplicated so the
     * rounding behavior can never drift between the two call sites.
     */
    static BigDecimal overallFromCategoryScores(Map<String, BigDecimal> categoryScores) {
        BigDecimal overall = BigDecimal.ZERO;
        for (String category : CATEGORIES) {
            overall = overall.add(categoryScores.get(category).multiply(CATEGORY_WEIGHTS.get(category)));
        }
        return overall.setScale(SCALE, RoundingMode.HALF_UP);
    }

    private static BigDecimal scoreCategory(
            List<Finding> allOpenFindings, String category, Map<String, BigDecimal> ruleWeights) {
        Map<String, List<Finding>> bySeverity = allOpenFindings.stream()
                .filter(f -> category.equals(f.category()))
                .collect(Collectors.groupingBy(Finding::severity, LinkedHashMap::new, Collectors.toList()));

        BigDecimal totalDeduction = BigDecimal.ZERO;
        for (Map.Entry<String, List<Finding>> entry : bySeverity.entrySet()) {
            List<Finding> group = ranked(entry.getValue(), ruleWeights);
            for (BigDecimal contribution : contributionsForRanked(group, entry.getKey(), ruleWeights)) {
                totalDeduction = totalDeduction.add(contribution);
            }
        }

        return clampAndRound(ONE_HUNDRED.subtract(totalDeduction));
    }

    /**
     * Deterministic tie-break for which finding lands in which discount
     * slot: highest rule-weight first (ties broken by ruleId), so the
     * most-heavily-weighted offenders are the ones scored at full strength
     * rather than an arbitrary/DB-order-dependent one. Package-visible so
     * {@link ScoreImpactCalculator} can look up a specific finding's rank
     * without duplicating this ordering - it must never drift from what
     * {@link #scoreCategory} actually uses.
     */
    static List<Finding> ranked(List<Finding> severityGroup, Map<String, BigDecimal> ruleWeights) {
        return severityGroup.stream()
                .sorted(Comparator
                        .comparing((Finding f) -> ruleWeights.getOrDefault(f.ruleId(), BigDecimal.ONE))
                        .reversed()
                        .thenComparing(Finding::ruleId))
                .toList();
    }

    /**
     * {@code 0.7^n} rounds to 0.00 (at the 2-decimal scale everything is
     * ultimately rounded to) once n passes roughly 130, since 0.7^130 is
     * already on the order of 1e-21 - far below anything a severityPoints*weight
     * multiplier (bounded in practice to double digits) could push back above
     * a hundredth. Ranks beyond this are exact zeroes, not approximations.
     */
    private static final int DIMINISHING_FACTOR_NEGLIGIBLE_RANK = 130;

    /**
     * Precision bound for {@code 0.7^n} itself. {@link BigDecimal#pow(int)}
     * with no MathContext computes an EXACT result - for 0.7 that means a
     * BigDecimal with n digits of scale, so at n in the tens of thousands
     * (confirmed live: a real target with a single category+severity group
     * that large) computing and then summing those exact powers becomes
     * catastrophically expensive BigInteger arithmetic, independent of - and
     * far worse than - the O(n) vs O(n^2) question this method's caller
     * otherwise cares about. 34 significant digits is far beyond what could
     * ever be observable after the final 2-decimal-place rounding.
     */
    private static final java.math.MathContext POW_PRECISION = java.math.MathContext.DECIMAL128;

    /**
     * Element {@code n} is {@code severityPoints * weight * 0.7^n} for the
     * nth entry of an already-{@link #ranked} group - package-visible so
     * {@link ScoreImpactCalculator} can get each finding's individual
     * discounted contribution (needed to compute a hypothetical "this finding
     * removed" total without re-summing the whole group) from the exact same
     * formula {@link #scoreCategory} uses.
     */
    static List<BigDecimal> contributionsForRanked(
            List<Finding> rankedGroup, String severity, Map<String, BigDecimal> ruleWeights) {
        BigDecimal severityPoints = SEVERITY_POINTS.getOrDefault(severity, BigDecimal.ZERO);
        List<BigDecimal> contributions = new java.util.ArrayList<>(rankedGroup.size());
        for (int n = 0; n < rankedGroup.size(); n++) {
            if (n >= DIMINISHING_FACTOR_NEGLIGIBLE_RANK) {
                contributions.add(BigDecimal.ZERO);
                continue;
            }
            BigDecimal weight = ruleWeights.getOrDefault(rankedGroup.get(n).ruleId(), BigDecimal.ONE);
            contributions.add(severityPoints.multiply(weight).multiply(DIMINISHING_FACTOR.pow(n, POW_PRECISION)));
        }
        return contributions;
    }

    static BigDecimal clampAndRound(BigDecimal value) {
        return clamp(value).setScale(SCALE, RoundingMode.HALF_UP);
    }

    private static BigDecimal clamp(BigDecimal value) {
        if (value.compareTo(BigDecimal.ZERO) < 0) {
            return BigDecimal.ZERO;
        }
        if (value.compareTo(ONE_HUNDRED) > 0) {
            return ONE_HUNDRED;
        }
        return value;
    }

    private static String gradeFor(BigDecimal overall) {
        if (overall.compareTo(new BigDecimal("90")) >= 0) return "A";
        if (overall.compareTo(new BigDecimal("80")) >= 0) return "B";
        if (overall.compareTo(new BigDecimal("70")) >= 0) return "C";
        if (overall.compareTo(new BigDecimal("60")) >= 0) return "D";
        return "F";
    }

    private static Map<String, Long> countBySeverity(List<Finding> openFindings) {
        Map<String, Long> counts = new TreeMap<>(Comparator.comparingInt(SEVERITY_ORDER::indexOf));
        for (String severity : SEVERITY_ORDER) {
            counts.put(severity, 0L);
        }
        for (Finding finding : openFindings) {
            counts.merge(finding.severity(), 1L, Long::sum);
        }
        return counts;
    }
}
