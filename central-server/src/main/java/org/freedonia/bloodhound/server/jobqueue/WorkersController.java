package org.freedonia.bloodhound.server.jobqueue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.dto.WorkerStatusDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Workers are global infrastructure shared across every organization in this
 * multi-tenant system - not org-scoped data. Every authenticated user can see every
 * worker's id/online-idle-busy status; only the *detail* of a busy job (target
 * hostname, module/tool) is redacted unless that job's target belongs to the
 * caller's own org, the same cross-tenant discipline the rest of this app applies to
 * IDOR-shaped data.
 */
@RestController
@RequestMapping("/api/v1/workers")
public class WorkersController {

    private final WorkerRepository workerRepository;
    private final Duration offlineThreshold;

    public WorkersController(
            WorkerRepository workerRepository,
            @Value("${bloodhound.worker.expected-poll-interval-ms:5000}") long expectedPollIntervalMs,
            @Value("${bloodhound.worker.expected-job-heartbeat-interval-ms:90000}") long expectedJobHeartbeatIntervalMs) {
        this.workerRepository = workerRepository;
        // Based on the LARGER of the two real presence signals, not just the poll
        // interval: an idle worker heartbeats every poll-interval-ms via /jobs/claim,
        // but a worker busy on one long-running job only heartbeats every
        // job-heartbeat-interval-ms (see JobLifecycleService.heartbeat) - basing this
        // on the fast interval alone would flap a genuinely-busy worker to OFFLINE
        // and back between its slower per-job heartbeats. 3x for jitter/single-miss slack.
        this.offlineThreshold = Duration.ofMillis(Math.max(expectedPollIntervalMs, expectedJobHeartbeatIntervalMs) * 3);
    }

    /**
     * Only genuinely-present workers are worth showing: a worker_id is stable for the
     * life of one process (see WorkerApplication), so every container restart/redeploy
     * mints a brand new one and leaves the old row behind forever with a heartbeat that
     * will never update again. Surfacing those as a growing list of "OFFLINE" entries
     * is pure accumulating clutter, not useful operational signal - so offline workers
     * are filtered out entirely rather than shown greyed-out.
     */
    @GetMapping
    public List<WorkerStatusDto> list(@AuthenticationPrincipal JwtPrincipal principal) {
        Instant now = Instant.now();
        return workerRepository.findAllWithJobDetail().stream()
                .filter(w -> isOnline(w, now))
                .map(w -> toDto(w, principal.organizationId()))
                .toList();
    }

    private boolean isOnline(WorkerRow w, Instant now) {
        return Duration.between(w.lastHeartbeatAt(), now).compareTo(offlineThreshold) <= 0;
    }

    private WorkerStatusDto toDto(WorkerRow w, java.util.UUID callerOrgId) {
        boolean busy = w.currentJobId() != null && w.moduleType() != null;
        if (!busy) {
            return new WorkerStatusDto(w.workerId(), "IDLE", w.lastHeartbeatAt(), null, null, null, null);
        }
        boolean ownOrg = callerOrgId.equals(w.targetOrganizationId());
        return new WorkerStatusDto(
                w.workerId(),
                "BUSY",
                w.lastHeartbeatAt(),
                ownOrg ? w.targetId() : null,
                ownOrg ? w.targetHostname() : null,
                ownOrg ? w.moduleType() : null,
                ownOrg ? w.currentHost() : null);
    }
}
