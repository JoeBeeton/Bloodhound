package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record ScoreSnapshot(
        UUID id,
        UUID targetId,
        UUID scanRunId,
        Instant computedAt,
        BigDecimal overallScore,
        String grade,
        Map<String, BigDecimal> categoryScores,
        Map<String, Long> findingCounts,
        // "Fair comparison" score computed from only the findings a Tier 1 (passive, always-run)
        // scan could have produced - excludes Tier 2-exclusive findings that only ever accumulate
        // on authorized (in practice: your own) targets. Null on snapshots taken before this was
        // added.
        BigDecimal tier1OverallScore,
        String tier1Grade,
        Map<String, BigDecimal> tier1CategoryScores) {}
