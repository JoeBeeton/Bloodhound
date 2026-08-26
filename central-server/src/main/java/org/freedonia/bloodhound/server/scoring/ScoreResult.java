package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.util.Map;

public record ScoreResult(
        BigDecimal overallScore, String grade, Map<String, BigDecimal> categoryScores, Map<String, Long> findingCounts) {}
