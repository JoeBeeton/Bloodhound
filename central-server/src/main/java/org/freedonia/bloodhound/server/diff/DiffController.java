package org.freedonia.bloodhound.server.diff;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.diff.dto.FindingDiffResponse;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRun;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Run-over-run findings diff: what's new, resolved, unchanged, or
 * severity-changed between two of a target's scan runs. {@code findings} is
 * a target-level rolling set (not stored per-run), so both sides are
 * reconstructed point-in-time via {@link FindingRepository#findOpenAsOf} and
 * compared by the pure {@link FindingDiffEngine}.
 */
@RestController
public class DiffController {

    private final TargetRepository targetRepository;
    private final ScanRunRepository scanRunRepository;
    private final FindingRepository findingRepository;
    private final ObjectMapper objectMapper;

    public DiffController(
            TargetRepository targetRepository,
            ScanRunRepository scanRunRepository,
            FindingRepository findingRepository,
            ObjectMapper objectMapper) {
        this.targetRepository = targetRepository;
        this.scanRunRepository = scanRunRepository;
        this.findingRepository = findingRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/api/v1/targets/{id}/runs/{runId}/diff")
    public FindingDiffResponse diff(
            @PathVariable UUID id,
            @PathVariable UUID runId,
            @RequestParam(defaultValue = "previous") String against,
            @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(DiffController::notFound);

        ScanRun compareRun = requireRunForTarget(runId, target.id());
        if (compareRun.completedAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "scan run has not completed yet");
        }

        // baselineRun is null when this is the target's first-ever completed
        // run (no ?against=previous candidate) - the diff then correctly
        // reports every currently-open finding as "new", which is the honest
        // answer rather than a special error case.
        ScanRun baselineRun;
        if ("previous".equals(against)) {
            baselineRun = scanRunRepository
                    .findPreviousCompleted(target.id(), compareRun.completedAt())
                    .orElse(null);
        } else {
            UUID baselineId;
            try {
                baselineId = UUID.fromString(against);
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "against must be 'previous' or a scan run id");
            }
            baselineRun = requireRunForTarget(baselineId, target.id());
            if (baselineRun.completedAt() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "baseline scan run has not completed yet");
            }
        }

        List<Finding> before =
                baselineRun != null ? findingRepository.findOpenAsOf(target.id(), baselineRun.completedAt()) : List.of();
        List<Finding> after = findingRepository.findOpenAsOf(target.id(), compareRun.completedAt());

        FindingDiffResult result = FindingDiffEngine.diff(before, after);
        return FindingDiffResponse.from(target.id(), baselineRun, compareRun, result, objectMapper);
    }

    private ScanRun requireRunForTarget(UUID runId, UUID targetId) {
        return scanRunRepository
                .findById(runId)
                .filter(run -> run.targetId().equals(targetId))
                .orElseThrow(DiffController::notFound);
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
