package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;

/**
 * "How much would the score improve if this finding were remediated?" - per finding,
 * keyed by finding id.
 *
 * <p>Computed by re-running the real {@link ScoringEngine} with each finding excluded
 * in turn and diffing against the baseline, rather than a hand-derived shortcut: the
 * {@code 0.7^n} diminishing-returns discount means removing one finding can shift the
 * discount rank (and therefore the deduction) of every other finding left in the same
 * category+severity group, so only re-running the real engine gets this right - e.g.
 * removing the 1st of three HIGH findings in a category is a different, larger delta
 * than removing the 3rd, because the two survivors' discount ranks (n=0,1) are not the
 * same set of ranks that survive if you remove the 3rd instead (still n=0,1 - but the
 * *identity* of who holds rank 0 changes, and for asymmetric rule weights the numeric
 * delta differs). See {@link ScoreImpactCalculatorTest} for a worked example.
 *
 * <p>One legitimate, provably-safe short-circuit: a finding whose category has no slot
 * in {@link ScoringEngine#CATEGORY_WEIGHTS} (WHOIS, WEB_APP) cannot affect any category
 * score no matter what else is in the findings list, since {@code scoreCategory} only
 * ever looks at findings matching its own category - removing it is skipped entirely
 * rather than paying for a no-op recomputation.
 */
public final class ScoreImpactCalculator {

    private ScoreImpactCalculator() {}

    public static Map<UUID, ScoreImpact> computeAll(List<Finding> openFindings, Map<String, BigDecimal> ruleWeights) {
        ScoreResult baseline = ScoringEngine.compute(openFindings, ruleWeights);
        Map<UUID, ScoreImpact> impacts = new LinkedHashMap<>();

        for (Finding finding : openFindings) {
            if (!ScoringEngine.CATEGORY_WEIGHTS.containsKey(finding.category())) {
                impacts.put(finding.id(), ScoreImpact.notApplicable(finding.category()));
                continue;
            }

            List<Finding> without = openFindings.stream()
                    .filter(f -> !f.id().equals(finding.id()))
                    .toList();
            ScoreResult hypothetical = ScoringEngine.compute(without, ruleWeights);

            BigDecimal before = baseline.categoryScores().get(finding.category());
            BigDecimal after = hypothetical.categoryScores().get(finding.category());
            BigDecimal overallDelta = hypothetical.overallScore().subtract(baseline.overallScore());

            impacts.put(finding.id(), new ScoreImpact(true, finding.category(), before, after, overallDelta));
        }

        return impacts;
    }
}
