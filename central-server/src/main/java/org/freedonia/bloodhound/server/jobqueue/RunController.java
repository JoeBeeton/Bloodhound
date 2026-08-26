package org.freedonia.bloodhound.server.jobqueue;

import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.dto.ScanRunDetail;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/runs")
public class RunController {

    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanJobAttemptRepository scanJobAttemptRepository;
    private final TargetRepository targetRepository;

    public RunController(
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            TargetRepository targetRepository) {
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
        this.targetRepository = targetRepository;
    }

    @GetMapping("/{id}")
    public ScanRunDetail get(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        ScanRun run = scanRunRepository.findById(id).orElseThrow(RunController::notFound);
        // Org-scoped via the run's target, same "404 not 403" convention as TargetController.
        Target target = targetRepository
                .findByIdAndOrganization(run.targetId(), principal.organizationId())
                .orElseThrow(RunController::notFound);

        var jobs = scanJobRepository.findByScanRunId(id).stream()
                .map(j -> new ScanRunDetail.ScanJobStatus(
                        j.id(),
                        j.moduleType(),
                        j.status(),
                        j.attemptCount(),
                        j.maxAttempts(),
                        j.errorDetail(),
                        scanJobAttemptRepository.findByScanJobId(j.id()).stream()
                                .map(a -> new ScanRunDetail.Attempt(
                                        a.attemptNumber(),
                                        a.claimedBy(),
                                        a.startedAt(),
                                        a.endedAt(),
                                        a.outcome(),
                                        a.errorDetail()))
                                .toList(),
                        JobPayloadHost.extract(j.payloadJson())))
                .toList();
        return new ScanRunDetail(
                run.id(),
                target.id(),
                target.hostname(),
                run.triggeredBy(),
                run.startedAt(),
                run.completedAt(),
                run.status(),
                jobs);
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
