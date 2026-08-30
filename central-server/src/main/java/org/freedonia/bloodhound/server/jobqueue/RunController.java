package org.freedonia.bloodhound.server.jobqueue;

import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.dto.ScanRunDetail;
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
        return ScanRunDetailComposer.compose(
                        id,
                        principal.organizationId(),
                        scanRunRepository,
                        scanJobRepository,
                        scanJobAttemptRepository,
                        targetRepository)
                .orElseThrow(RunController::notFound);
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
