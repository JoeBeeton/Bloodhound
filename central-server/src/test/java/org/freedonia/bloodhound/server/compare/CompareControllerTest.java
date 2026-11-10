package org.freedonia.bloodhound.server.compare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.compare.dto.TrendPoint;
import org.freedonia.bloodhound.server.portfolio.Portfolio;
import org.freedonia.bloodhound.server.portfolio.PortfolioRepository;
import org.freedonia.bloodhound.server.portfolio.PortfolioService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class CompareControllerTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final PortfolioRepository portfolioRepository = mock(PortfolioRepository.class);
    private final PortfolioService portfolioService = mock(PortfolioService.class);
    private final CompareController controller = new CompareController(
            targetRepository, scoreSnapshotRepository, portfolioRepository, portfolioService);

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "u@example.com");

    private Target target(UUID id) {
        return new Target(id, orgId, "host-" + id, "OWN", "AUTHORIZED", 86400, Instant.now(), true, Instant.now(), null);
    }

    private Portfolio portfolio(UUID id) {
        return new Portfolio(id, orgId, "portfolio-" + id, Instant.now());
    }

    @Test
    void tooManyTargetIds_rejected_neverQueriesAnyRepository() {
        // An input-validation review found this had no bound at all - a crafted request with a
        // very long targetIds list would drive a proportionally long chain of sequential
        // findByIdAndOrganization + score-history lookups, one pair per id.
        List<UUID> tooMany = Stream.generate(UUID::randomUUID).limit(21).toList();

        assertThatThrownBy(() -> controller.compare(tooMany, null, "all", principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
        verify(targetRepository, never()).findByIdAndOrganization(any(), any());
        verify(scoreSnapshotRepository, never()).findDailyHistory(any(), any(), any());
    }

    @Test
    void tooManyCombinedTargetAndPortfolioIds_rejected() {
        List<UUID> targets = Stream.generate(UUID::randomUUID).limit(15).toList();
        List<UUID> portfolios = Stream.generate(UUID::randomUUID).limit(6).toList();

        assertThatThrownBy(() -> controller.compare(targets, portfolios, "all", principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void withinBound_stillReturnsASeriesPerTarget() {
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();
        when(targetRepository.findByIdAndOrganization(id1, orgId)).thenReturn(Optional.of(target(id1)));
        when(targetRepository.findByIdAndOrganization(id2, orgId)).thenReturn(Optional.of(target(id2)));
        when(scoreSnapshotRepository.findDailyHistory(any(), any(), any())).thenReturn(Map.of());
        when(scoreSnapshotRepository.findLatestForTargets(any())).thenReturn(Map.of());

        var result = controller.compare(List.of(id1, id2), null, "all", principal);

        assertThat(result).hasSize(2);
        assertThat(result).allSatisfy(s -> {
            assertThat(s.points()).isEmpty();
            assertThat(s.latest()).isNull();
        });
    }

    @Test
    void portfolioIdsAlone_noTargetIds_returnsOneSeriesPerPortfolio() {
        UUID portfolioId = UUID.randomUUID();
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio(portfolioId)));
        when(portfolioService.computeBlendedHistory(any(), any(), any())).thenReturn(List.of());

        var result = controller.compare(null, List.of(portfolioId), "all", principal);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).targetType()).isEqualTo("PORTFOLIO");
    }

    private ScoreSnapshot snapshot(UUID targetId, Instant at, String score, String tier1) {
        return new ScoreSnapshot(UUID.randomUUID(), targetId, UUID.randomUUID(), at, new BigDecimal(score), "B",
                Map.of("TLS", new BigDecimal("70")), Map.of("HIGH", 2L), new BigDecimal(tier1), "B", null);
    }

    @Test
    void pointsCarryOnlyTheTrendFields_latestCarriesTheFullBreakdown() {
        UUID id = UUID.randomUUID();
        Instant day1 = Instant.parse("2026-11-01T18:00:00Z");
        Instant day2 = Instant.parse("2026-11-02T09:00:00Z");
        when(targetRepository.findByIdAndOrganization(id, orgId)).thenReturn(Optional.of(target(id)));
        when(scoreSnapshotRepository.findDailyHistory(eq(List.of(id)), any(), any()))
                .thenReturn(Map.of(id, List.of(snapshot(id, day1, "60", "65"), snapshot(id, day2, "70", "75"))));
        when(scoreSnapshotRepository.findLatestForTargets(List.of(id)))
                .thenReturn(Map.of(id, snapshot(id, day2, "70", "75")));

        var series = controller.compare(List.of(id), null, "90d", principal).get(0);

        assertThat(series.points()).extracting(TrendPoint::computedAt).containsExactly(day1, day2);
        assertThat(series.points().get(1).tier1OverallScore()).isEqualByComparingTo("75");
        assertThat(series.latest().categoryScores()).containsKey("TLS");
        assertThat(series.latest().findingCounts()).containsEntry("HIGH", 2L);
    }

    @Test
    void rangeAll_hasNoLowerBound_rangeDays_boundsFromThatManyDaysBack() {
        UUID id = UUID.randomUUID();
        when(targetRepository.findByIdAndOrganization(id, orgId)).thenReturn(Optional.of(target(id)));
        when(scoreSnapshotRepository.findDailyHistory(any(), any(), any())).thenReturn(Map.of());
        when(scoreSnapshotRepository.findLatestForTargets(any())).thenReturn(Map.of());

        controller.compare(List.of(id), null, "all", principal);
        verify(scoreSnapshotRepository).findDailyHistory(eq(List.of(id)), isNull(), any());

        Instant before = Instant.now();
        controller.compare(List.of(id), null, "1y", principal);
        verify(scoreSnapshotRepository).findDailyHistory(
                eq(List.of(id)),
                argThat(from -> from != null
                        && !from.isAfter(before.minus(365, ChronoUnit.DAYS).plusSeconds(5))
                        && !from.isBefore(before.minus(365, ChronoUnit.DAYS).minusSeconds(5))),
                any());
    }

    @Test
    void unknownRange_rejected() {
        assertThatThrownBy(() -> controller.compare(List.of(UUID.randomUUID()), null, "5y", principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void portfolioInAnotherOrg_notFound() {
        UUID portfolioId = UUID.randomUUID();
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.compare(null, List.of(portfolioId), "all", principal))
                .isInstanceOf(ResponseStatusException.class);
    }
}
