package org.freedonia.bloodhound.worker.jobpoll;

import java.util.List;
import java.util.Optional;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.worker.jobpoll.dto.ClaimRequest;
import org.freedonia.bloodhound.worker.jobpoll.dto.ClaimedJob;
import org.freedonia.bloodhound.worker.jobpoll.dto.FailRequest;
import org.freedonia.bloodhound.worker.jobpoll.dto.FindingPayload;
import org.freedonia.bloodhound.worker.jobpoll.dto.ResultRequest;
import org.freedonia.bloodhound.worker.modules.ScanModuleRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Claims jobs from central-server, dispatches each to the ScanModule
 * registered for its module_type, and reports the outcome back.
 *
 * <p>Jobs claimed in one poll cycle are executed sequentially, one at a
 * time (see {@link #poll}) - not concurrently. Because a job's lease clock
 * starts ticking the moment it's claimed, not when this loop actually starts
 * executing it, a claimed-but-not-yet-started job sitting behind another one
 * in the same batch gets no heartbeat protection at all until its turn
 * comes. With the default capacity of 1 (see worker/application.yml) this
 * never happens; it's called out here as a known limitation if capacity is
 * ever configured above 1 without also making dispatch concurrent.
 */
@Component
public class JobPollingLoop {

    private static final Logger log = LoggerFactory.getLogger(JobPollingLoop.class);
    private static final ParameterizedTypeReference<List<ClaimedJob>> CLAIMED_JOBS_TYPE =
            new ParameterizedTypeReference<>() {};

    private final RestClient centralServerClient;
    private final ScanModuleRegistry registry;
    private final JobHeartbeatSender heartbeatSender;
    private final String workerId;
    private final int capacity;

    public JobPollingLoop(
            RestClient centralServerClient,
            ScanModuleRegistry registry,
            JobHeartbeatSender heartbeatSender,
            String workerId,
            @Value("${bloodhound.worker.capacity:1}") int capacity) {
        this.centralServerClient = centralServerClient;
        this.registry = registry;
        this.heartbeatSender = heartbeatSender;
        this.workerId = workerId;
        this.capacity = capacity;
    }

    @Scheduled(fixedDelayString = "${bloodhound.poll-interval-ms:5000}")
    public void poll() {
        List<ClaimedJob> jobs;
        try {
            jobs = centralServerClient
                    .post()
                    .uri("/api/v1/jobs/claim")
                    .body(new ClaimRequest(workerId, capacity))
                    .retrieve()
                    .body(CLAIMED_JOBS_TYPE);
        } catch (Exception e) {
            log.warn("job claim failed: {}", e.getMessage());
            return;
        }
        if (jobs == null || jobs.isEmpty()) {
            return;
        }
        jobs.forEach(this::executeAndReport);
    }

    private void executeAndReport(ClaimedJob job) {
        log.info("claimed job {} module={} target={}", job.id(), job.moduleType(), job.hostname());
        Optional<ScanModule> module = registry.find(job.moduleType());
        if (module.isEmpty()) {
            reportFailure(job, "no worker module registered for type " + job.moduleType());
            return;
        }
        JobHeartbeatSender.Handle heartbeat = heartbeatSender.start(job.id());
        try {
            ScanContext context = new ScanContext(job.targetId(), job.hostname(), List.of(), job.payload());
            ModuleResult result = module.get().execute(context);
            reportResult(job, result);
        } catch (ScanModuleException e) {
            String detail = withCause(e);
            log.warn("job {} failed: {}", job.id(), detail);
            reportFailure(job, detail);
        } catch (Exception e) {
            log.error("job {} failed unexpectedly", job.id(), e);
            reportFailure(job, "unexpected error: " + e.getMessage());
        } finally {
            heartbeat.stop();
        }
    }

    /**
     * ScanModuleException's own message ({@code e.getMessage()}) is deliberately terse ("failed
     * to reach ZAP at ...") - a stable, addressable string for the outer failure, not a dump of
     * the wire-level cause. But that cause (a raw java.io.IOException - could be connection
     * refused, a read timeout, a reset, ...) was previously logged nowhere at all: neither the
     * worker's own log line nor the error_detail persisted to scan_jobs (and shown in the UI)
     * carried it, making a real failure (confirmed live: OWASP ZAP's single shared sidecar
     * pegging CPU under concurrent scan load and timing out its own status-check API) look
     * identical to a dozen other possible causes from the log/UI alone. Appends the cause's own
     * class + message when present so this is diagnosable without shelling into a container.
     */
    private static String withCause(ScanModuleException e) {
        Throwable cause = e.getCause();
        if (cause == null) {
            return e.getMessage();
        }
        return e.getMessage() + " (caused by " + cause.getClass().getSimpleName() + ": " + cause.getMessage() + ")";
    }

    private void reportResult(ClaimedJob job, ModuleResult result) {
        try {
            List<FindingPayload> findings = result.findings().stream()
                    .map(f -> new FindingPayload(
                            f.ruleId(),
                            f.severity().name(),
                            f.category().name(),
                            f.title(),
                            f.description(),
                            f.affectedAsset(),
                            f.evidence()))
                    .toList();
            centralServerClient
                    .post()
                    .uri("/api/v1/jobs/{id}/result", job.id())
                    .body(new ResultRequest(workerId, findings, result.rawMetadata()))
                    .retrieve()
                    .toBodilessEntity();
            log.info("job {} complete, {} finding(s) reported", job.id(), findings.size());
        } catch (Exception e) {
            log.error("failed to report result for job {}: {}", job.id(), e.getMessage());
        }
    }

    private void reportFailure(ClaimedJob job, String errorDetail) {
        try {
            centralServerClient
                    .post()
                    .uri("/api/v1/jobs/{id}/fail", job.id())
                    .body(new FailRequest(workerId, errorDetail))
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            log.error("failed to report failure for job {}: {}", job.id(), e.getMessage());
        }
    }
}
