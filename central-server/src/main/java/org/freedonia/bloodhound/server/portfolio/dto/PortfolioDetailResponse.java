package org.freedonia.bloodhound.server.portfolio.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.server.portfolio.PortfolioDetail;
import org.freedonia.bloodhound.server.portfolio.PortfolioMemberScore;
import org.freedonia.bloodhound.server.target.Target;

public record PortfolioDetailResponse(
        UUID id, String name, Instant createdAt, BigDecimal blendedScore, String blendedGrade, List<PortfolioMemberDetail> members) {

    public static PortfolioDetailResponse from(PortfolioDetail detail) {
        Map<UUID, PortfolioMemberScore> scoreByTargetId = detail.scoredMembers().stream()
                .collect(Collectors.toMap(PortfolioMemberScore::targetId, s -> s));
        // detail.members() is already hostname-sorted (see TargetRepository#findByPortfolio) -
        // preserved here rather than grouping "all scored" before "all unscored", so the member
        // list reads the same order a user would expect from any other alphabetized target list.
        List<PortfolioMemberDetail> members = new java.util.ArrayList<>();
        for (Target target : detail.members()) {
            PortfolioMemberScore score = scoreByTargetId.get(target.id());
            members.add(score != null ? PortfolioMemberDetail.scored(score) : PortfolioMemberDetail.unscored(target));
        }
        return new PortfolioDetailResponse(
                detail.portfolio().id(),
                detail.portfolio().name(),
                detail.portfolio().createdAt(),
                detail.blendedScore(),
                detail.blendedGrade(),
                members);
    }
}
