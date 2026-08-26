package org.freedonia.bloodhound.server.scoring;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class ScoreController {

    /** Default lookback when no ?from is given - the plan doesn't mandate a value, 90 days is a sensible default trend window. */
    private static final int DEFAULT_LOOKBACK_DAYS = 90;

    private final ScoreSnapshotRepository scoreSnapshotRepository;
    private final TargetRepository targetRepository;

    public ScoreController(ScoreSnapshotRepository scoreSnapshotRepository, TargetRepository targetRepository) {
        this.scoreSnapshotRepository = scoreSnapshotRepository;
        this.targetRepository = targetRepository;
    }

    @GetMapping("/api/v1/targets/{id}/score/history")
    public List<ScoreSnapshotSummary> history(
            @PathVariable UUID id,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Instant effectiveTo = to != null ? to : Instant.now();
        Instant effectiveFrom = from != null ? from : effectiveTo.minus(DEFAULT_LOOKBACK_DAYS, ChronoUnit.DAYS);
        return scoreSnapshotRepository.findHistory(target.id(), effectiveFrom, effectiveTo).stream()
                .map(ScoreSnapshotSummary::from)
                .toList();
    }
}
