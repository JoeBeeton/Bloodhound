package org.freedonia.bloodhound.server.compare;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.compare.dto.CompareSeries;
import org.freedonia.bloodhound.server.portfolio.Portfolio;
import org.freedonia.bloodhound.server.portfolio.PortfolioRepository;
import org.freedonia.bloodhound.server.portfolio.PortfolioService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The "our score vs. competitors over time" endpoint: a fan-out of the same
 * per-target score-history query {@link org.freedonia.bloodhound.server.scoring.ScoreController}
 * already exposes, across multiple target ids in one response shaped for a
 * multi-line chart.
 */
@RestController
public class CompareController {

    private static final int DEFAULT_LOOKBACK_DAYS = 90;

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

    /**
     * @param portfolioIds each resolves to one blended series (see PortfolioService#computeBlendedHistory),
     *     appended after the individual-target series so a portfolio's line has a stable position
     *     regardless of how many targetIds were selected alongside it.
     */
    @GetMapping("/api/v1/compare")
    public List<CompareSeries> compare(
            @RequestParam(required = false) List<UUID> targetIds,
            @RequestParam(required = false) List<UUID> portfolioIds,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @AuthenticationPrincipal JwtPrincipal principal) {
        List<UUID> effectiveTargetIds = targetIds != null ? targetIds : List.of();
        List<UUID> effectivePortfolioIds = portfolioIds != null ? portfolioIds : List.of();
        if (effectiveTargetIds.size() + effectivePortfolioIds.size() > MAX_COMPARE_TARGETS) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "too many targetIds/portfolioIds (max " + MAX_COMPARE_TARGETS + " combined)");
        }
        Instant effectiveTo = to != null ? to : Instant.now();
        Instant effectiveFrom = from != null ? from : effectiveTo.minus(DEFAULT_LOOKBACK_DAYS, ChronoUnit.DAYS);

        List<CompareSeries> targetSeries = effectiveTargetIds.stream()
                .map(id -> targetRepository
                        .findByIdAndOrganization(id, principal.organizationId())
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .map(target -> CompareSeries.of(target, history(target, effectiveFrom, effectiveTo)))
                .toList();
        List<CompareSeries> portfolioSeries = effectivePortfolioIds.stream()
                .map(id -> portfolioRepository
                        .findByIdAndOrganization(id, principal.organizationId())
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .map(portfolio -> CompareSeries.ofPortfolio(
                        portfolio, portfolioService.computeBlendedHistory(portfolio, effectiveFrom, effectiveTo)))
                .toList();

        return Stream.concat(targetSeries.stream(), portfolioSeries.stream()).toList();
    }

    private List<ScoreSnapshotSummary> history(Target target, Instant from, Instant to) {
        return scoreSnapshotRepository.findHistory(target.id(), from, to).stream()
                .map(ScoreSnapshotSummary::from)
                .toList();
    }
}
