package org.freedonia.bloodhound.server.portfolio;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;

/** Pure-function tests against PortfolioService#blendedScore (no mocking needed, package-private access) plus instance tests against #computeBlendedHistory (mocked repositories). */
class PortfolioServiceTest {

    private static PortfolioMemberScore member(BigDecimal score, long findings) {
        return new PortfolioMemberScore(UUID.randomUUID(), "example.com", score, "A", findings);
    }

    @Test
    void emptyList_returnsNull() {
        assertThat(PortfolioService.blendedScore(List.of())).isNull();
    }

    @Test
    void singleMember_returnsItsOwnScore() {
        BigDecimal blended = PortfolioService.blendedScore(List.of(member(new BigDecimal("87.50"), 5)));

        assertThat(blended).isEqualByComparingTo("87.50");
    }

    @Test
    void twoMembers_weightedByOpenFindingCount_notFlatMidpoint() {
        // 95-scoring domain with 1 open finding vs. a 40-scoring domain with 19 - the blend
        // should sit much closer to 40 (where the real risk is) than the flat midpoint (67.5).
        List<PortfolioMemberScore> scored =
                List.of(member(new BigDecimal("95"), 1), member(new BigDecimal("40"), 19));

        BigDecimal blended = PortfolioService.blendedScore(scored);

        // (95*1 + 40*19) / 20 = (95 + 760) / 20 = 855/20 = 42.75
        assertThat(blended).isEqualByComparingTo("42.75");
    }

    @Test
    void allMembersZeroOpenFindings_fallsBackToPlainMean() {
        List<PortfolioMemberScore> scored =
                List.of(member(new BigDecimal("90"), 0), member(new BigDecimal("100"), 0));

        BigDecimal blended = PortfolioService.blendedScore(scored);

        assertThat(blended).isEqualByComparingTo("95.00");
    }

    @Test
    void mixOfZeroAndNonZeroFindings_zeroFindingMembersStillCountInWeightedAverage() {
        // A member with zero findings contributes weight 0 (its score doesn't move the blend at
        // all) rather than being excluded or falling back to the plain-mean path - only an
        // *all-zero* set triggers the fallback.
        List<PortfolioMemberScore> scored =
                List.of(member(new BigDecimal("100"), 0), member(new BigDecimal("50"), 10));

        BigDecimal blended = PortfolioService.blendedScore(scored);

        // (100*0 + 50*10) / 10 = 500/10 = 50.00
        assertThat(blended).isEqualByComparingTo("50.00");
    }

    // --- computeBlendedHistory: instance tests against mocked repositories ---

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final PortfolioService service = new PortfolioService(targetRepository, scoreSnapshotRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID portfolioId = UUID.randomUUID();
    private final Instant t0 = Instant.now();
    private final Instant t1 = t0.plus(1, ChronoUnit.HOURS);
    private final Instant t2 = t0.plus(2, ChronoUnit.HOURS);
    private final Instant t3 = t0.plus(3, ChronoUnit.HOURS);

    private Target target(String hostname) {
        return new Target(UUID.randomUUID(), orgId, hostname, "OWN", "AUTHORIZED", 86400, Instant.now(), true, Instant.now(), null);
    }

    private ScoreSnapshot snapshot(Instant computedAt, String score, long findingCount, String tier1Score) {
        return new ScoreSnapshot(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                computedAt,
                new BigDecimal(score),
                "A",
                Map.of(),
                Map.of("HIGH", findingCount),
                tier1Score != null ? new BigDecimal(tier1Score) : null,
                tier1Score != null ? "A" : null,
                null);
    }

    @Test
    void computeBlendedHistory_noMembers_returnsEmptyList() {
        Portfolio portfolio = new Portfolio(portfolioId, orgId, "empty", Instant.now());
        when(targetRepository.findByPortfolio(portfolioId)).thenReturn(List.of());

        List<ScoreSnapshotSummary> history = service.computeBlendedHistory(portfolio, t0, t3);

        assertThat(history).isEmpty();
    }

    @Test
    void computeBlendedHistory_staggeredTimestamps_carriesForwardAndExcludesUnscoredMembers() {
        Portfolio portfolio = new Portfolio(portfolioId, orgId, "staggered", Instant.now());
        Target a = target("a.example.com");
        Target b = target("b.example.com");
        when(targetRepository.findByPortfolio(portfolioId)).thenReturn(List.of(a, b));

        // A has snapshots at t1 and t3; B only joins at t2 - change points are the union: t1,t2,t3.
        when(scoreSnapshotRepository.findHistory(eq(a.id()), any(), any()))
                .thenReturn(List.of(snapshot(t1, "90", 2, null), snapshot(t3, "80", 5, null)));
        when(scoreSnapshotRepository.findHistory(eq(b.id()), any(), any()))
                .thenReturn(List.of(snapshot(t2, "60", 10, null)));

        List<ScoreSnapshotSummary> history = service.computeBlendedHistory(portfolio, t0, t3);

        assertThat(history).hasSize(3);
        // t1: only A is known yet - the blend is exactly A's own score, B isn't treated as 0.
        assertThat(history.get(0).computedAt()).isEqualTo(t1);
        assertThat(history.get(0).overallScore()).isEqualByComparingTo("90.00");
        // t2: A still at its t1 snapshot (90/2), B now known (60/10) - (90*2+60*10)/12 = 65.00
        assertThat(history.get(1).computedAt()).isEqualTo(t2);
        assertThat(history.get(1).overallScore()).isEqualByComparingTo("65.00");
        // t3: A updates to (80/5), B still at (60/10) - (80*5+60*10)/15 = 66.67
        assertThat(history.get(2).computedAt()).isEqualTo(t3);
        assertThat(history.get(2).overallScore()).isEqualByComparingTo("66.67");
    }

    @Test
    void computeBlendedHistory_nullTier1Score_fallsBackToFullScore() {
        Portfolio portfolio = new Portfolio(portfolioId, orgId, "tier1-fallback", Instant.now());
        Target a = target("a.example.com");
        when(targetRepository.findByPortfolio(portfolioId)).thenReturn(List.of(a));
        // No tier1 score on this snapshot (pre-tier1-feature, or a Tier 2-only host) - the blend's
        // tier1 value should fall back to the full overallScore, same as CompareTrendChart.tsx
        // already does per-point for a real target's own history.
        when(scoreSnapshotRepository.findHistory(eq(a.id()), any(), any()))
                .thenReturn(List.of(snapshot(t1, "77", 3, null)));

        List<ScoreSnapshotSummary> history = service.computeBlendedHistory(portfolio, t0, t3);

        assertThat(history).hasSize(1);
        assertThat(history.get(0).overallScore()).isEqualByComparingTo("77.00");
        assertThat(history.get(0).tier1OverallScore()).isEqualByComparingTo("77.00");
    }

    @Test
    void computeBlendedHistory_noSnapshotsInWindow_returnsEmptyList() {
        Portfolio portfolio = new Portfolio(portfolioId, orgId, "no-history", Instant.now());
        Target a = target("a.example.com");
        when(targetRepository.findByPortfolio(portfolioId)).thenReturn(List.of(a));
        when(scoreSnapshotRepository.findHistory(eq(a.id()), any(), any())).thenReturn(List.of());

        List<ScoreSnapshotSummary> history = service.computeBlendedHistory(portfolio, t0, t3);

        assertThat(history).isEmpty();
    }
}
