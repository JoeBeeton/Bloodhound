package org.freedonia.bloodhound.server.portfolio.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.portfolio.PortfolioDetail;

/** List-view row - the member detail list itself is only fetched on the portfolio's own detail page, not here. */
public record PortfolioSummary(
        UUID id,
        String name,
        Instant createdAt,
        BigDecimal blendedScore,
        String blendedGrade,
        int memberCount,
        int unscoredMemberCount) {

    public static PortfolioSummary from(PortfolioDetail detail) {
        return new PortfolioSummary(
                detail.portfolio().id(),
                detail.portfolio().name(),
                detail.portfolio().createdAt(),
                detail.blendedScore(),
                detail.blendedGrade(),
                detail.members().size(),
                detail.unscoredTargetIds().size());
    }
}
