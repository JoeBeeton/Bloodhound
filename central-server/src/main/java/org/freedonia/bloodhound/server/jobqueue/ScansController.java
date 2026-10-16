package org.freedonia.bloodhound.server.jobqueue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.Estimate;
import org.freedonia.bloodhound.server.jobqueue.ScanEtaEstimator.JobProgress;
import org.freedonia.bloodhound.server.jobqueue.dto.ActiveScan;
import org.springframework.http.ResponseEntity;
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
        // Same reasoning for the concurrency-cap queue depth: ZAP_ACTIVE_SCAN's one global slot is
        // shared across every org/target's scan_run, not just whichever one we're estimating right
        // now - see ScanEtaEstimator's own javadoc on why this made the old max-based ETA wrong by
        // an order of magnitude for a target queued behind another target's ZAP jobs.
        Map<String, Integer> concurrencyCaps = Map.of("ZAP_ACTIVE_SCAN", scanJobRepository.zapMaxConcurrentScans());
        Map<String, Integer> systemWideRemaining = new java.util.HashMap<>();
        concurrencyCaps.keySet().forEach(
                moduleType -> systemWideRemaining.put(moduleType, scanJobRepository.countPendingOrInProgress(moduleType)));

        return runs.stream()
                .map(orgRun -> {
                    ScanRun run = orgRun.run();
                    List<ScanJob> jobs = scanJobRepository.findByScanRunId(run.id());
                    List<JobProgress> progress = jobs.stream()
                            .map(j -> new JobProgress(j.moduleType(), j.status(), j.claimedAt()))
                            .toList();
                    Estimate est = ScanEtaEstimator.estimate(
                            progress, avgSeconds, systemWideRemaining, concurrencyCaps, java.time.Instant.now());
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
     * Per-module-type caps on how many jobs of that type can be CLAIMED/RUNNING at once,
     * independent of worker count - currently just ZAP_ACTIVE_SCAN (see ScanJobRepository#claim's
     * own javadoc for why: a single shared zap sidecar, not scaled per worker). A live report
     * ("workers 2 and 3 sit idle while a scan is running") turned out to be this cap working as
     * intended, not a claim bug - {@link #active} already shows a capped job sitting PENDING
     * alongside a RUNNING one of the same module_type, but gives no way to tell "queued because
     * nothing else claimed it yet" from "queued because this module type is deliberately
     * throttled". Kept as its own tiny endpoint rather than folded into {@link #active}'s
     * per-run/ETA shape, and returned as a flat module_type -> limit map so a future second capped
     * module type needs no frontend contract change, just a new entry here.
     */
    @GetMapping("/queue-limits")
    public Map<String, Integer> queueLimits() {
        return Map.of("ZAP_ACTIVE_SCAN", scanJobRepository.zapMaxConcurrentScans());
    }

    private static final int MAX_RECENT_LIMIT = 200;

    /**
     * Past scans (any status - including FAILED/PARTIAL_FAILURE), most recent first. {@link
     * #active} only ever shows RUNNING runs, so a scan that fails vanishes from it the moment it
     * reaches a terminal state - this is what makes a since-failed scan findable/diagnosable
     * again afterward, linking through to RunController's per-attempt failure detail.
     *
     * <p>status/offset are new - a product review found this list had no way to narrow past a
     * fixed most-recent-30, despite "did target X's scan actually fail last night" being exactly
     * the kind of question status filtering (plus paging back further than 30) answers. limit is
     * unchanged in meaning/default so any existing caller (the docs-listed external API, MCP)
     * keeps working; the X-Total-Count header is new, same convention as the other paginated list
     * endpoints in this app (AuditLogController, FindingController).
     */
    @GetMapping("/recent")
    public ResponseEntity<List<RecentScan>> recent(
            @AuthenticationPrincipal JwtPrincipal principal,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "30") int limit,
            @RequestParam(defaultValue = "0") int offset) {
        int boundedLimit = Math.clamp(limit, 1, MAX_RECENT_LIMIT);
        int boundedOffset = Math.max(offset, 0);
        List<RecentScan> page = scanRunRepository
                .findRecentByOrganization(principal.organizationId(), status, boundedLimit, boundedOffset)
                .stream()
                .map(r -> new RecentScan(
                        r.run().id(),
                        r.run().targetId(),
                        r.targetHostname(),
                        r.run().triggeredBy(),
                        r.run().status(),
                        r.run().startedAt(),
                        r.run().completedAt()))
                .toList();
        int totalCount = scanRunRepository.countRecentByOrganization(principal.organizationId(), status);
        return ResponseEntity.ok().header("X-Total-Count", String.valueOf(totalCount)).body(page);
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
