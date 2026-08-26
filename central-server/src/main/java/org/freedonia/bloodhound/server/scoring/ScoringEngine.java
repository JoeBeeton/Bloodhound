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
    private static final BigDecimal DIMINISHING_FACTOR = new BigDecimal("0.7");

    private static final BigDecimal ONE_HUNDRED = new BigDecimal("100");
    private static final int SCALE = 2;

    private ScoringEngine() {}

    public static ScoreResult compute(List<Finding> openFindings, Map<String, BigDecimal> ruleWeights) {
        Map<String, BigDecimal> categoryScores = new LinkedHashMap<>();
        for (String category : CATEGORIES) {
            categoryScores.put(category, scoreCategory(openFindings, category, ruleWeights));
        }

        BigDecimal overall = BigDecimal.ZERO;
        for (String category : CATEGORIES) {
            overall = overall.add(categoryScores.get(category).multiply(CATEGORY_WEIGHTS.get(category)));
        }
        overall = overall.setScale(SCALE, RoundingMode.HALF_UP);

        return new ScoreResult(overall, gradeFor(overall), categoryScores, countBySeverity(openFindings));
    }

    private static BigDecimal scoreCategory(
            List<Finding> allOpenFindings, String category, Map<String, BigDecimal> ruleWeights) {
        Map<String, List<Finding>> bySeverity = allOpenFindings.stream()
                .filter(f -> category.equals(f.category()))
                .collect(Collectors.groupingBy(Finding::severity, LinkedHashMap::new, Collectors.toList()));

        BigDecimal totalDeduction = BigDecimal.ZERO;
        for (Map.Entry<String, List<Finding>> entry : bySeverity.entrySet()) {
            BigDecimal severityPoints = SEVERITY_POINTS.getOrDefault(entry.getKey(), BigDecimal.ZERO);
            // Deterministic tie-break for which finding lands in which discount
            // slot: highest rule-weight first (ties broken by ruleId), so the
            // most-heavily-weighted offenders are the ones scored at full
            // strength rather than an arbitrary/DB-order-dependent one.
            List<Finding> group = entry.getValue().stream()
                    .sorted(Comparator
                            .comparing((Finding f) -> ruleWeights.getOrDefault(f.ruleId(), BigDecimal.ONE))
                            .reversed()
                            .thenComparing(Finding::ruleId))
                    .toList();
            for (int n = 0; n < group.size(); n++) {
                Finding finding = group.get(n);
                BigDecimal weight = ruleWeights.getOrDefault(finding.ruleId(), BigDecimal.ONE);
                BigDecimal discount = DIMINISHING_FACTOR.pow(n);
                totalDeduction = totalDeduction.add(severityPoints.multiply(weight).multiply(discount));
            }
        }

        BigDecimal raw = ONE_HUNDRED.subtract(totalDeduction);
        return clamp(raw).setScale(SCALE, RoundingMode.HALF_UP);
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
