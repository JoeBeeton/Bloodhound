package org.freedonia.bloodhound.server.scoring.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;

public record ScoreSnapshotSummary(
        UUID id,
        UUID scanRunId,
        Instant computedAt,
        BigDecimal overallScore,
        String grade,
        Map<String, BigDecimal> categoryScores,
        Map<String, Long> findingCounts,
        // "Fair comparison" score excluding Tier 2-exclusive findings - null on snapshots
        // taken before this was added.
        BigDecimal tier1OverallScore,
        String tier1Grade,
        Map<String, BigDecimal> tier1CategoryScores) {
    public static ScoreSnapshotSummary from(ScoreSnapshot snapshot) {
        return new ScoreSnapshotSummary(
                snapshot.id(),
                snapshot.scanRunId(),
                snapshot.computedAt(),
                snapshot.overallScore(),
                snapshot.grade(),
                snapshot.categoryScores(),
                snapshot.findingCounts(),
                snapshot.tier1OverallScore(),
                snapshot.tier1Grade(),
                snapshot.tier1CategoryScores());
    }
}
