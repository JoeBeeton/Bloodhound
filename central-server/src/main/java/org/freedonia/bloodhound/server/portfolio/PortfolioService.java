package org.freedonia.bloodhound.server.portfolio;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.scoring.ScoringEngine;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.stereotype.Service;

/** Computes a portfolio's blended score(s) from its member targets' own ScoreSnapshots - never stores anything itself, always derived live from data each target's own scan pipeline already produces. */
@Service
public class PortfolioService {

    private final TargetRepository targetRepository;
    private final ScoreSnapshotRepository scoreSnapshotRepository;

    public PortfolioService(TargetRepository targetRepository, ScoreSnapshotRepository scoreSnapshotRepository) {
        this.targetRepository = targetRepository;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
    }

    public PortfolioDetail computeDetail(Portfolio portfolio) {
        List<Target> members = targetRepository.findByPortfolio(portfolio.id());
        Map<UUID, ScoreSnapshot> latest =
                scoreSnapshotRepository.findLatestForTargets(members.stream().map(Target::id).toList());

        List<PortfolioMemberScore> scored = new ArrayList<>();
        List<UUID> unscoredTargetIds = new ArrayList<>();
        for (Target target : members) {
            ScoreSnapshot snapshot = latest.get(target.id());
            if (snapshot == null) {
                unscoredTargetIds.add(target.id());
                continue;
            }
            long totalFindings =
                    snapshot.findingCounts().values().stream().mapToLong(Long::longValue).sum();
            scored.add(new PortfolioMemberScore(
                    target.id(), target.hostname(), snapshot.overallScore(), snapshot.grade(), totalFindings));
        }

        BigDecimal blended = blendedScore(scored);
        String blendedGrade = blended != null ? ScoringEngine.gradeFor(blended) : null;
        return new PortfolioDetail(portfolio, blended, blendedGrade, members, scored, unscoredTargetIds);
    }

    /**
     * A portfolio's blended score *over time*, for the Compare page's trend chart - the historical
     * generalization of {@link #computeDetail}'s single "as of right now" blend. Each member scans
     * on its own schedule (same reason CompareTrendChart plots each real target's own history as
     * its own independently-timed series rather than a shared bucketed axis), so this walks the
     * sorted union of every member's own snapshot timestamps in the window ("change points") and,
     * at each one, blends whichever members have a known snapshot as of that point yet (a member
     * with no snapshot yet is excluded, not treated as 0 - same rule as {@link #computeDetail}) -
     * a simple per-member "most recent snapshot seen so far" cursor, advanced as change points are
     * walked in order.
     *
     * <p>No carry-forward from before {@code from}: an individual target's own series in Compare
     * doesn't get that either (see CompareTrendChart's own "targets with no history yet are
     * silently skipped" comment), so a portfolio's blended line starts exactly where its members'
     * real data starts, not before.
     *
     * <p>Each point carries both a full-score blend and a tier1-score blend, substituting
     * {@code tier1OverallScore ?? overallScore} per member first - the exact same fallback
     * CompareTrendChart.tsx already applies per-point to a real target's history, so a portfolio's
     * Fair-comparison/Full-picture toggle behaves identically to an individual target's.
     *
     * <p>categoryScores/tier1CategoryScores and findingCounts are genuinely blended too, not left
     * empty - a security/correctness review found the Categories view's "weakest category" label
     * crashed outright on a portfolio series (reading a score out of what was always an empty map,
     * then calling {@code .toFixed} on the resulting {@code undefined}), and the Findings view
     * silently showed every portfolio as having zero open findings for the same reason. Every
     * real target's own {@code categoryScores}/{@code findingCounts} always carries a complete set
     * of keys (ScoringEngine always writes one entry per category/severity, even when zero), so
     * summing per-key across {@code current.values()} is safe without needing a fixed category/
     * severity list here. Category scores are weighted-averaged the same way overallScore is,
     * since they're themselves a score; findingCounts are summed outright, since a portfolio's
     * real open-finding count is the total across its members, not an average of them.
     */
    public List<ScoreSnapshotSummary> computeBlendedHistory(Portfolio portfolio, Instant from, Instant to) {
        List<Target> members = targetRepository.findByPortfolio(portfolio.id());
        Map<UUID, List<ScoreSnapshot>> historyByMember = new HashMap<>();
        TreeSet<Instant> changePoints = new TreeSet<>();
        for (Target target : members) {
            List<ScoreSnapshot> history = scoreSnapshotRepository.findHistory(target.id(), from, to);
            historyByMember.put(target.id(), history);
            history.forEach(s -> changePoints.add(s.computedAt()));
        }

        Map<UUID, Integer> cursor = new HashMap<>();
        Map<UUID, ScoreSnapshot> current = new HashMap<>();
        List<ScoreSnapshotSummary> result = new ArrayList<>();
        for (Instant point : changePoints) {
            for (Target target : members) {
                List<ScoreSnapshot> history = historyByMember.get(target.id());
                int idx = cursor.getOrDefault(target.id(), 0);
                while (idx < history.size() && !history.get(idx).computedAt().isAfter(point)) {
                    current.put(target.id(), history.get(idx));
                    idx++;
                }
                cursor.put(target.id(), idx);
            }
            if (current.isEmpty()) {
                continue;
            }
            List<BigDecimal> fullScores = new ArrayList<>();
            List<BigDecimal> tier1Scores = new ArrayList<>();
            List<Long> weights = new ArrayList<>();
            Map<String, List<BigDecimal>> categoryScoresByCategory = new LinkedHashMap<>();
            Map<String, List<BigDecimal>> tier1CategoryScoresByCategory = new LinkedHashMap<>();
            Map<String, Long> findingCountTotals = new LinkedHashMap<>();
            for (ScoreSnapshot snapshot : current.values()) {
                fullScores.add(snapshot.overallScore());
                tier1Scores.add(snapshot.tier1OverallScore() != null ? snapshot.tier1OverallScore() : snapshot.overallScore());
                weights.add(snapshot.findingCounts().values().stream()
                        .mapToLong(Long::longValue)
                        .sum());
                snapshot.categoryScores()
                        .forEach((category, score) ->
                                categoryScoresByCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(score));
                Map<String, BigDecimal> tier1Categories =
                        snapshot.tier1CategoryScores() != null ? snapshot.tier1CategoryScores() : snapshot.categoryScores();
                tier1Categories.forEach((category, score) -> tier1CategoryScoresByCategory
                        .computeIfAbsent(category, k -> new ArrayList<>())
                        .add(score));
                snapshot.findingCounts().forEach((severity, count) -> findingCountTotals.merge(severity, count, Long::sum));
            }
            BigDecimal blendedFull = weightedAverage(fullScores, weights);
            BigDecimal blendedTier1 = weightedAverage(tier1Scores, weights);
            Map<String, BigDecimal> blendedCategoryScores = new LinkedHashMap<>();
            categoryScoresByCategory.forEach(
                    (category, scores) -> blendedCategoryScores.put(category, weightedAverage(scores, weights)));
            Map<String, BigDecimal> blendedTier1CategoryScores = new LinkedHashMap<>();
            tier1CategoryScoresByCategory.forEach(
                    (category, scores) -> blendedTier1CategoryScores.put(category, weightedAverage(scores, weights)));
            result.add(new ScoreSnapshotSummary(
                    UUID.randomUUID(),
                    null,
                    point,
                    blendedFull,
                    ScoringEngine.gradeFor(blendedFull),
                    blendedCategoryScores,
                    findingCountTotals,
                    blendedTier1,
                    ScoringEngine.gradeFor(blendedTier1),
                    blendedTier1CategoryScores));
        }
        return result;
    }

    /**
     * Weighted average of each scored member's overallScore, weighted by that member's own total
     * open-finding count (summed across its latest snapshot's severities) - a portfolio pairing a
     * quiet 95-scoring domain against a 40-scoring one crawling with open findings should read
     * close to 40, since that's where the organization's real risk actually sits, not a flat
     * midpoint. Weighting by subdomain/attack-surface size instead was considered and rejected:
     * that conflates inventory size with risk, so a huge but perfectly clean estate would wrongly
     * dominate the blend.
     *
     * <p>Package-private and pure (no repository calls) so it's directly unit-testable without
     * mocking anything - see PortfolioServiceTest.
     */
    static BigDecimal blendedScore(List<PortfolioMemberScore> scored) {
        if (scored.isEmpty()) {
            return null;
        }
        List<BigDecimal> scores = scored.stream().map(PortfolioMemberScore::overallScore).toList();
        List<Long> weights = scored.stream().map(PortfolioMemberScore::totalOpenFindings).toList();
        return weightedAverage(scores, weights);
    }

    /**
     * Falls back to a plain unweighted mean when every weight is zero - the weighted formula is
     * otherwise 0/0 (undefined), and an all-clean set should show its true high average rather
     * than blow up or silently show null. Shared by both the single-point blend
     * ({@link #blendedScore}) and the historical blend ({@link #computeBlendedHistory}) so the
     * two can never drift apart.
     */
    private static BigDecimal weightedAverage(List<BigDecimal> scores, List<Long> weights) {
        long totalWeight = weights.stream().mapToLong(Long::longValue).sum();
        if (totalWeight == 0) {
            BigDecimal sum = scores.stream().reduce(BigDecimal.ZERO, BigDecimal::add);
            return sum.divide(BigDecimal.valueOf(scores.size()), 2, RoundingMode.HALF_UP);
        }
        BigDecimal weightedSum = BigDecimal.ZERO;
        for (int i = 0; i < scores.size(); i++) {
            weightedSum = weightedSum.add(scores.get(i).multiply(BigDecimal.valueOf(weights.get(i))));
        }
        return weightedSum.divide(BigDecimal.valueOf(totalWeight), 2, RoundingMode.HALF_UP);
    }
}
