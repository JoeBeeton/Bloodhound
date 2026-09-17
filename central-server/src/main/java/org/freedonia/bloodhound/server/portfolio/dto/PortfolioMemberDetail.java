package org.freedonia.bloodhound.server.portfolio.dto;

import java.math.BigDecimal;
import java.util.UUID;
import org.freedonia.bloodhound.server.portfolio.PortfolioMemberScore;
import org.freedonia.bloodhound.server.target.Target;

/** One member row for the portfolio detail view - scored and not-yet-scored members share this one shape (hasScore flags the difference) rather than two separate arrays, since the frontend renders them in one list either way. */
public record PortfolioMemberDetail(UUID targetId, String hostname, BigDecimal overallScore, String grade, boolean hasScore) {

    public static PortfolioMemberDetail scored(PortfolioMemberScore score) {
        return new PortfolioMemberDetail(score.targetId(), score.hostname(), score.overallScore(), score.grade(), true);
    }

    public static PortfolioMemberDetail unscored(Target target) {
        return new PortfolioMemberDetail(target.id(), target.hostname(), null, null, false);
    }
}
