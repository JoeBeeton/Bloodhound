package org.freedonia.bloodhound.server.portfolio;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Pure-function tests against PortfolioService#blendedScore - no mocking needed, package-private access. */
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
}
