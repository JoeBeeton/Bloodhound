package org.freedonia.bloodhound.server.compare.dto;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.portfolio.Portfolio;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;

/**
 * One series on the Compare page - a single target, or a portfolio's blend (see
 * PortfolioService#computeBlendedHistory) shaped identically so the frontend renders either with
 * no special-casing. targetType is "PORTFOLIO" for the latter - a plain string, not an enum, so
 * it needed no schema change.
 *
 * <p>{@code points} is one point per UTC day within the requested range, for the trend line and
 * the leaderboard's change column. {@code latest} is the most recent snapshot regardless of range
 * (null if never scored), for every "as of now" view. Earlier this sent every raw snapshot in
 * full, and the client derived both - several MB per selection change.
 */
public record CompareSeries(
        UUID targetId, String hostname, String targetType, List<TrendPoint> points, ScoreSnapshotSummary latest) {

    public static CompareSeries of(Target target, List<TrendPoint> points, ScoreSnapshotSummary latest) {
        return new CompareSeries(target.id(), target.hostname(), target.targetType(), points, latest);
    }

    public static CompareSeries ofPortfolio(Portfolio portfolio, List<TrendPoint> points, ScoreSnapshotSummary latest) {
        return new CompareSeries(portfolio.id(), portfolio.name(), "PORTFOLIO", points, latest);
    }
}
