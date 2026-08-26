package org.freedonia.bloodhound.server.target.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.target.Target;

public record TargetSummary(
        UUID id,
        String hostname,
        String targetType,
        String authorizationStatus,
        int scanCadenceSeconds,
        Instant nextScanAt,
        boolean isActive,
        Instant createdAt,
        BigDecimal overallScore,
        String grade,
        // "Fair comparison" score excluding Tier 2-exclusive findings - null on targets that
        // haven't been scanned since this was added.
        BigDecimal tier1OverallScore,
        String tier1Grade) {

    /** No scan has ever completed for this target yet - score/grade are absent, not zero. */
    public static TargetSummary from(Target target) {
        return from(target, null);
    }

    public static TargetSummary from(Target target, ScoreSnapshot latestScore) {
        return new TargetSummary(
                target.id(),
                target.hostname(),
                target.targetType(),
                target.authorizationStatus(),
                target.scanCadenceSeconds(),
                target.nextScanAt(),
                target.isActive(),
                target.createdAt(),
                latestScore != null ? latestScore.overallScore() : null,
                latestScore != null ? latestScore.grade() : null,
                latestScore != null ? latestScore.tier1OverallScore() : null,
                latestScore != null ? latestScore.tier1Grade() : null);
    }
}
