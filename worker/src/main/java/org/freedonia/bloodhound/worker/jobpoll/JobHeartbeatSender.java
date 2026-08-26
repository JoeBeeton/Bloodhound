package org.freedonia.bloodhound.worker.jobpoll;

import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.worker.jobpoll.dto.WorkerScopedRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Sends {@code PATCH /jobs/{id}/heartbeat} on a fixed interval for as long as
 * a module's {@code execute()} call is still in flight, so the central-server
 * lease reaper never reclaims a job that's still genuinely running.
 *
 * <p>Added in Milestone 8 after finding heartbeating had only ever been
 * wired up as a central-server endpoint - nothing on the worker side called
 * it. That was harmless for Milestone 2's NOOP module (1.5s, well inside the
 * 5-minute lease) but is a real gap for modules like SUBDOMAIN_ENUM, whose
 * worst case (subfinder's own ~60-90s timeout, plus crt.sh latency, plus DNS
 * resolution and dangling-CNAME confirmation for up to 500 hosts) can
 * plausibly approach several minutes.
 *
 * <p>The heartbeat interval (default 90s) is deliberately well inside the
 * lease window (default 5 minutes) so a single missed/slow heartbeat call
 * doesn't risk the lease expiring anyway; this was judged simpler and more
 * robust than trying to give individual module types their own lease
 * duration.
 */
@Component
public class JobHeartbeatSender {

    private static final Logger log = LoggerFactory.getLogger(JobHeartbeatSender.class);

    private final RestClient centralServerClient;
    private final String workerId;
    private final long intervalMs;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "job-heartbeat-sender");
                t.setDaemon(true);
                return t;
            });

    public JobHeartbeatSender(
            RestClient centralServerClient,
            String workerId,
            @Value("${bloodhound.worker.heartbeat-interval-ms:90000}") long intervalMs) {
        this.centralServerClient = centralServerClient;
        this.workerId = workerId;
        this.intervalMs = intervalMs;
    }

    /** Starts periodic heartbeating for a claimed job; call {@link Handle#stop()} once execution finishes. */
    public Handle start(UUID jobId) {
        ScheduledFuture<?> future = scheduler.scheduleAtFixedRate(
                () -> sendOnce(jobId), intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        return () -> future.cancel(false);
    }

    private void sendOnce(UUID jobId) {
        try {
            centralServerClient
                    .patch()
                    .uri("/api/v1/jobs/{id}/heartbeat", jobId)
                    .body(new WorkerScopedRequest(workerId))
                    .retrieve()
                    .toBodilessEntity();
            log.debug("heartbeat sent for job {}", jobId);
        } catch (Exception e) {
            // Nothing recoverable to do here mid-execution - if the lease genuinely
            // expires despite this, the job either gets reaped (safe: claimed_by
            // ownership checks on result/fail prevent any double-counting) or this
            // worker's eventual result/fail report is simply rejected as stale.
            log.warn("heartbeat failed for job {}: {}", jobId, e.getMessage());
        }
    }

    /** Cancels the periodic heartbeat task. Not blocking, safe to call multiple times. */
    public interface Handle {
        void stop();
    }
}
