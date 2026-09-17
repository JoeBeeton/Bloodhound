package org.freedonia.bloodhound.server.compare.dto;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.portfolio.Portfolio;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;

/**
 * One series in a multi-line trend chart - either a single target's own score history, or a
 * portfolio's blended history (see PortfolioService#computeBlendedHistory) shaped identically so
 * CompareTrendChart.tsx can render either kind with no special-casing. targetType is "PORTFOLIO"
 * for the latter - a plain string, not an enum, specifically so this didn't need a schema change.
 */
public record CompareSeries(UUID targetId, String hostname, String targetType, List<ScoreSnapshotSummary> history) {

    public static CompareSeries of(Target target, List<ScoreSnapshotSummary> history) {
        return new CompareSeries(target.id(), target.hostname(), target.targetType(), history);
    }

    public static CompareSeries ofPortfolio(Portfolio portfolio, List<ScoreSnapshotSummary> history) {
        return new CompareSeries(portfolio.id(), portfolio.name(), "PORTFOLIO", history);
    }
}
