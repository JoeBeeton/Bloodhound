package org.freedonia.bloodhound.server.compare;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.compare.dto.CompareSeries;
import org.freedonia.bloodhound.server.compare.dto.TrendPoint;
import org.freedonia.bloodhound.server.portfolio.Portfolio;
import org.freedonia.bloodhound.server.portfolio.PortfolioRepository;
import org.freedonia.bloodhound.server.portfolio.PortfolioService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshot;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The "our score vs. competitors over time" endpoint: every selected target's and portfolio's
 * daily trend points plus its latest snapshot, in one response. The reduction to one point per
 * day happens here, not in the browser - see {@link CompareSeries}.
 */
@RestController
public class CompareController {

    // The compare chart is a handful-of-competitors comparison by design - the UI never offers a
    // way to select more than a few. This is defensive, not a real user-facing limit: an
    // input-validation review found targetIds had no bound at all, so a crafted request with a
    // very long id list would drive a proportionally long chain of sequential
    // findByIdAndOrganization + score-history lookups per request.
    private static final int MAX_COMPARE_TARGETS = 20;

    private final TargetRepository targetRepository;
    private final ScoreSnapshotRepository scoreSnapshotRepository;
    private final PortfolioRepository portfolioRepository;
    private final PortfolioService portfolioService;

    public CompareController(
            TargetRepository targetRepository,
            ScoreSnapshotRepository scoreSnapshotRepository,
            PortfolioRepository portfolioRepository,
            PortfolioService portfolioService) {
        this.targetRepository = targetRepository;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
        this.portfolioRepository = portfolioRepository;
        this.portfolioService = portfolioService;
    }

    /** Range keys the Compare page offers; anything else is a 400. */
    private static final Map<String, Integer> RANGE_DAYS = Map.of("30d", 30, "90d", 90, "1y", 365);

    /**
     * @param portfolioIds each resolves to one blended series (see PortfolioService#computeBlendedHistory),
     *     appended after the individual-target series so a portfolio's line has a stable position
     *     regardless of how many targetIds were selected alongside it.
     * @param range 30d, 90d, 1y or all (the default). Bounds {@code points} only - {@code latest}
     *     is always the most recent snapshot. Before this existed the endpoint silently applied a
     *     90-day default the page never overrode, so "1y" and "All time" both showed 90 days.
     */
    @GetMapping("/api/v1/compare")
    public List<CompareSeries> compare(
            @RequestParam(required = false) List<UUID> targetIds,
            @RequestParam(required = false) List<UUID> portfolioIds,
            @RequestParam(required = false, defaultValue = "all") String range,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<UUID> effectiveTargetIds = targetIds != null ? targetIds : List.of();
        List<UUID> effectivePortfolioIds = portfolioIds != null ? portfolioIds : List.of();
        if (effectiveTargetIds.size() + effectivePortfolioIds.size() > MAX_COMPARE_TARGETS) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "too many targetIds/portfolioIds (max " + MAX_COMPARE_TARGETS + " combined)");
        }
        if (!"all".equals(range) && !RANGE_DAYS.containsKey(range)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "range must be one of 30d, 90d, 1y, all");
        }
        Instant to = Instant.now();
        Instant from = "all".equals(range) ? null : to.minus(RANGE_DAYS.get(range), ChronoUnit.DAYS);

        List<Target> targets = effectiveTargetIds.stream()
                .map(id -> targetRepository
                        .findByIdAndOrganization(id, principal.organizationId())
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .toList();
        List<UUID> ids = targets.stream().map(Target::id).toList();
        Map<UUID, List<ScoreSnapshot>> daily = scoreSnapshotRepository.findDailyHistory(ids, from, to);
        Map<UUID, ScoreSnapshot> latest = scoreSnapshotRepository.findLatestForTargets(ids);
        List<CompareSeries> targetSeries = targets.stream()
                .map(target -> CompareSeries.of(
                        target,
                        daily.getOrDefault(target.id(), List.of()).stream().map(TrendPoint::of).toList(),
                        latest.containsKey(target.id()) ? ScoreSnapshotSummary.from(latest.get(target.id())) : null))
                .toList();

        List<CompareSeries> portfolioSeries = effectivePortfolioIds.stream()
                .map(id -> portfolioRepository
                        .findByIdAndOrganization(id, principal.organizationId())
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .map(portfolio -> CompareSeries.ofPortfolio(
                        portfolio,
                        portfolioService.computeBlendedHistory(portfolio, from, to).stream()
                                .map(TrendPoint::of)
                                .toList(),
                        portfolioService.computeBlendedLatest(portfolio)))
                .toList();

        return Stream.concat(targetSeries.stream(), portfolioSeries.stream()).toList();
    }
}
