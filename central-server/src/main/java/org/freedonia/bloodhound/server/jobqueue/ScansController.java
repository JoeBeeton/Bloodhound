package org.freedonia.bloodhound.server.jobqueue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.Estimate;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.JobProgress;
import org.freedonia.bloodhound.server.jobqueue.dto.ActiveScan;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** "What's happening right now" - the live active-scans list, distinct from RunController's single-run detail. */
@RestController
@RequestMapping("/api/v1/scans")
public class ScansController {

    /** How many recent real completions to average per module_type - see ScanJobAttemptRepository. */
    private static final int ETA_SAMPLE_SIZE = 30;

    private final ScanRunRepository scanRunRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanJobAttemptRepository scanJobAttemptRepository;

    public ScansController(
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository) {
        this.scanRunRepository = scanRunRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
    }

    @GetMapping("/active")
    public List<ActiveScan> active(@AuthenticationPrincipal JwtPrincipal principal) {
        List<OrgScanRun> runs = scanRunRepository.findRunningByOrganization(principal.organizationId());
        if (runs.isEmpty()) {
            return List.of();
        }
        // One shared historical-average lookup for every run in this response, not one per run -
        // the averages are global (per module_type), not per-run, so there's no reason to repeat it.
        Map<String, Double> avgSeconds = scanJobAttemptRepository.averageSecondsByModuleType(ETA_SAMPLE_SIZE);

        return runs.stream()
                .map(orgRun -> {
                    ScanRun run = orgRun.run();
                    List<ScanJob> jobs = scanJobRepository.findByScanRunId(run.id());
                    List<JobProgress> progress = jobs.stream()
                            .map(j -> new JobProgress(j.moduleType(), j.status(), j.claimedAt()))
                            .toList();
                    Estimate est = ScanEtaEstimator.estimate(progress, avgSeconds, java.time.Instant.now());
                    List<ActiveScan.ModuleProgress> modules = jobs.stream()
                            .map(j -> new ActiveScan.ModuleProgress(
                                    j.moduleType(), j.status(), JobPayloadHost.extract(j.payloadJson())))
                            .toList();
                    return new ActiveScan(
                            run.id(),
                            run.targetId(),
                            orgRun.targetHostname(),
                            run.triggeredBy(),
                            run.startedAt(),
                            est.completedJobs(),
                            est.totalJobs(),
                            est.etaSeconds(),
                            modules);
                })
                .toList();
    }

    /**
     * Past scans (any status - including FAILED/PARTIAL_FAILURE), most recent first. {@link
     * #active} only ever shows RUNNING runs, so a scan that fails vanishes from it the moment it
     * reaches a terminal state - this is what makes a since-failed scan findable/diagnosable
     * again afterward, linking through to RunController's per-attempt failure detail.
     */
    @GetMapping("/recent")
    public List<RecentScan> recent(
            @AuthenticationPrincipal JwtPrincipal principal, @RequestParam(defaultValue = "30") int limit) {
        return scanRunRepository.findRecentByOrganization(principal.organizationId(), limit).stream()
                .map(r -> new RecentScan(
                        r.run().id(),
                        r.run().targetId(),
                        r.targetHostname(),
                        r.run().triggeredBy(),
                        r.run().status(),
                        r.run().startedAt(),
                        r.run().completedAt()))
                .toList();
    }

    public record RecentScan(
            UUID id,
            UUID targetId,
            String targetHostname,
            String triggeredBy,
            String status,
            Instant startedAt,
            Instant completedAt) {}
}
