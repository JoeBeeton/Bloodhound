package org.freedonia.bloodhound.server.compare;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.compare.dto.CompareSeries;
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

    public CompareController(TargetRepository targetRepository, ScoreSnapshotRepository scoreSnapshotRepository) {
        this.targetRepository = targetRepository;
        this.scoreSnapshotRepository = scoreSnapshotRepository;
    }

    @GetMapping("/api/v1/compare")
    public List<CompareSeries> compare(
            @RequestParam List<UUID> targetIds,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @AuthenticationPrincipal JwtPrincipal principal) {
        if (targetIds.size() > MAX_COMPARE_TARGETS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "too many targetIds (max " + MAX_COMPARE_TARGETS + ")");
        }
        Instant effectiveTo = to != null ? to : Instant.now();
        Instant effectiveFrom = from != null ? from : effectiveTo.minus(DEFAULT_LOOKBACK_DAYS, ChronoUnit.DAYS);

        return targetIds.stream()
                .map(id -> targetRepository
                        .findByIdAndOrganization(id, principal.organizationId())
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .map(target -> CompareSeries.of(target, history(target, effectiveFrom, effectiveTo)))
                .toList();
    }

    private List<ScoreSnapshotSummary> history(Target target, Instant from, Instant to) {
        return scoreSnapshotRepository.findHistory(target.id(), from, to).stream()
                .map(ScoreSnapshotSummary::from)
                .toList();
    }
}
