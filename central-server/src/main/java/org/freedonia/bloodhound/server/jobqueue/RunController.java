package org.freedonia.bloodhound.server.jobqueue;

import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.dto.ScanRunDetail;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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
    private final ScanRunService scanRunService;

    public RunController(
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            TargetRepository targetRepository,
            ScanRunService scanRunService) {
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
        this.targetRepository = targetRepository;
        this.scanRunService = scanRunService;
    }

    @GetMapping("/{id}")
    public ScanRunDetail get(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        return compose(id, principal).orElseThrow(RunController::notFound);
    }

    /**
     * Stops a running scan - see ScanRunService#cancel for what does and doesn't get interrupted.
     * 409, not a silent no-op, if the run has already finished (COMPLETE/FAILED/CANCELLED) by the
     * time this request lands - a stale "Cancel" click racing the scan's own completion should
     * tell the user that, not pretend it worked.
     */
    @PostMapping("/{id}/cancel")
    public ScanRunDetail cancel(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        ScanRunDetail before = compose(id, principal).orElseThrow(RunController::notFound);
        if (!"RUNNING".equals(before.status())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "This scan has already finished.");
        }
        scanRunService.cancel(id);
        return compose(id, principal).orElseThrow(RunController::notFound);
    }

    private java.util.Optional<ScanRunDetail> compose(UUID id, JwtPrincipal principal) {
        return ScanRunDetailComposer.compose(
                id, principal.organizationId(), scanRunRepository, scanJobRepository, scanJobAttemptRepository, targetRepository);
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
