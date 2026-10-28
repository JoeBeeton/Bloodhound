package org.freedonia.bloodhound.server.portfolio.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.portfolio.PortfolioDetail;
import org.freedonia.bloodhound.server.target.Target;

/**
 * List-view row - the member detail list itself is only fetched on the portfolio's own detail
 * page, not here, except for the bare id list below: ComparePage needs to know which targets a
 * portfolio already represents so it can default-exclude them from its own target selection (a
 * portfolio's blended line already covers its members - selecting both by default would double
 * them up). Free to add: {@link PortfolioDetail#members()} is already computed for every
 * portfolio in {@code PortfolioController#list}, this just stops dropping it on the floor.
 */
public record PortfolioSummary(
        UUID id,
        String name,
        Instant createdAt,
        BigDecimal blendedScore,
        String blendedGrade,
        int memberCount,
        int unscoredMemberCount,
        List<UUID> memberTargetIds) {

    public static PortfolioSummary from(PortfolioDetail detail) {
        return new PortfolioSummary(
                detail.portfolio().id(),
                detail.portfolio().name(),
                detail.portfolio().createdAt(),
                detail.blendedScore(),
                detail.blendedGrade(),
                detail.members().size(),
                detail.unscoredTargetIds().size(),
                detail.members().stream().map(Target::id).toList());
    }
}
