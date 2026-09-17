package org.freedonia.bloodhound.server.portfolio;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.target.Target;

/**
 * Full computed view of a portfolio - blendedScore/blendedGrade are null when no member has ever
 * been scanned. unscoredTargetIds lets a caller say "N targets not yet scored" without folding
 * them into the blend as if they were a real (e.g. zero) risk signal.
 */
public record PortfolioDetail(
        Portfolio portfolio,
        BigDecimal blendedScore,
        String blendedGrade,
        List<Target> members,
        List<PortfolioMemberScore> scoredMembers,
        List<UUID> unscoredTargetIds) {}
