package org.freedonia.bloodhound.server.compare.dto;

import java.math.BigDecimal;
import java.time.Instant;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;

/**
 * One point on a Compare trend line - only what the line needs. The full breakdown (category
 * scores, finding counts) is sent once per series as {@link CompareSeries#latest()}, not on every
 * point. tier1OverallScore is null on snapshots taken before the fair-comparison score existed.
 */
public record TrendPoint(Instant computedAt, BigDecimal overallScore, BigDecimal tier1OverallScore) {

    public static TrendPoint of(ScoreSnapshot s) {
        return new TrendPoint(s.computedAt(), s.overallScore(), s.tier1OverallScore());
    }

    public static TrendPoint of(ScoreSnapshotSummary s) {
        return new TrendPoint(s.computedAt(), s.overallScore(), s.tier1OverallScore());
    }
}
