package org.freedonia.bloodhound.server.portfolio;

import java.math.BigDecimal;
import java.util.UUID;

/** One scored member's contribution to a portfolio's blended score - see PortfolioService#blendedScore. */
public record PortfolioMemberScore(
        UUID targetId, String hostname, BigDecimal overallScore, String grade, long totalOpenFindings) {}
