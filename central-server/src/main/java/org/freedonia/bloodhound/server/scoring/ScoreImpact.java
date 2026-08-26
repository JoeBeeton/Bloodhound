package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;

/**
 * How much a target's score would change if one specific finding were remediated.
 *
 * <p>{@code affectsScore} is false for findings in a category outside {@link
 * ScoringEngine#CATEGORY_WEIGHTS} (e.g. WHOIS, WEB_APP) - those mathematically
 * cannot move the score, so {@code categoryScoreBefore}/{@code categoryScoreAfter}/
 * {@code overallScoreDelta} are all null rather than a possibly-misleading zero,
 * so the frontend can distinguish "fixing this won't move the score" from "this
 * category isn't scored at all."
 */
public record ScoreImpact(
        boolean affectsScore,
        String category,
        BigDecimal categoryScoreBefore,
        BigDecimal categoryScoreAfter,
        BigDecimal overallScoreDelta) {

    static ScoreImpact notApplicable(String category) {
        return new ScoreImpact(false, category, null, null, null);
    }
}
