package org.freedonia.bloodhound.server.portfolio;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.scoring.ScoringEngine;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.stereotype.Service;

/** Computes a portfolio's blended score from its member targets' own latest ScoreSnapshots - never stores anything itself, always derived live from data each target's own scan pipeline already produces. */
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
     * Weighted average of each scored member's overallScore, weighted by that member's own total
     * open-finding count (summed across its latest snapshot's severities) - a portfolio pairing a
     * quiet 95-scoring domain against a 40-scoring one crawling with open findings should read
     * close to 40, since that's where the organization's real risk actually sits, not a flat
     * midpoint. Weighting by subdomain/attack-surface size instead was considered and rejected:
     * that conflates inventory size with risk, so a huge but perfectly clean estate would wrongly
     * dominate the blend.
     *
     * <p>Falls back to a plain unweighted mean when every scored member currently has zero open
     * findings - the weighted formula is otherwise 0/0 (undefined), and an all-clean portfolio
     * should show its true high average rather than blow up or silently show null.
     *
     * <p>Package-private and pure (no repository calls) so it's directly unit-testable without
     * mocking anything - see PortfolioServiceTest.
     */
    static BigDecimal blendedScore(List<PortfolioMemberScore> scored) {
        if (scored.isEmpty()) {
            return null;
        }
        long totalWeight =
                scored.stream().mapToLong(PortfolioMemberScore::totalOpenFindings).sum();
        if (totalWeight == 0) {
            BigDecimal sum = scored.stream()
                    .map(PortfolioMemberScore::overallScore)
                    .reduce(BigDecimal.ZERO, BigDecimal::add);
            return sum.divide(BigDecimal.valueOf(scored.size()), 2, RoundingMode.HALF_UP);
        }
        BigDecimal weightedSum = scored.stream()
                .map(m -> m.overallScore().multiply(BigDecimal.valueOf(m.totalOpenFindings())))
                .reduce(BigDecimal.ZERO, BigDecimal::add);
        return weightedSum.divide(BigDecimal.valueOf(totalWeight), 2, RoundingMode.HALF_UP);
    }
}
