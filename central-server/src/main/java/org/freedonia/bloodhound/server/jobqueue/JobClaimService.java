package org.freedonia.bloodhound.server.jobqueue;

import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Claims jobs on behalf of polling workers, and reaps leases that expired
 * without a heartbeat/result so a crashed or network-partitioned worker
 * doesn't strand a job forever. Both operate through
 * {@link ScanJobRepository}'s single-statement, FOR UPDATE SKIP LOCKED-backed
 * SQL - the correctness property that matters here (no job double-claimed,
 * none silently dropped) lives in that SQL, not in this class.
 */
@Service
public class JobClaimService {

    private static final Logger log = LoggerFactory.getLogger(JobClaimService.class);

    private final ScanJobRepository scanJobRepository;
    private final ScanJobAttemptRepository scanJobAttemptRepository;
    private final ScanRunService scanRunService;
    private final WorkerRepository workerRepository;
    private final int leaseMinutes;

    public JobClaimService(
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            ScanRunService scanRunService,
            WorkerRepository workerRepository,
            @Value("${bloodhound.jobqueue.lease-minutes:5}") int leaseMinutes) {
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
        this.scanRunService = scanRunService;
        this.workerRepository = workerRepository;
        this.leaseMinutes = leaseMinutes;
    }

    public List<ScanJob> claim(String workerId, int capacity) {
        // Recorded on every call, whether or not a job is actually returned below - this
        // is what makes an idle worker (nothing to claim) still show up as online in
        // WorkersController, since it's polling this endpoint on a fixed interval either way.
        workerRepository.heartbeat(workerId);
        List<ScanJob> claimed = scanJobRepository.claim(workerId, capacity, leaseMinutes);
        // attemptCount on the row is the count *before* this try (0 for a fresh job) - +1 makes
        // the logged attempt_number 1-indexed, matching how a human reads a retry timeline.
        claimed.forEach(job -> {
            scanJobAttemptRepository.startAttempt(job.id(), job.attemptCount() + 1, workerId);
            workerRepository.setCurrentJob(workerId, job.id());
        });
        return claimed;
    }

    @Scheduled(fixedDelayString = "${bloodhound.jobqueue.reaper-interval-ms:30000}")
    public void reapExpiredLeases() {
        List<ScanJobRepository.ReapedJob> reaped = scanJobRepository.reapExpiredLeases();
        if (!reaped.isEmpty()) {
            log.warn("lease reaper: {} job(s) had an expired lease", reaped.size());
        }
        reaped.forEach(r -> {
            scanJobAttemptRepository.completeAttempt(r.jobId(), "TIMED_OUT_REAPED", "lease expired without heartbeat/result");
            if (r.workerId() != null) {
                workerRepository.clearCurrentJob(r.workerId(), r.jobId());
            }
        });
        reaped.stream()
                .filter(r -> "FAILED".equals(r.newStatus()))
                .map(ScanJobRepository.ReapedJob::scanRunId)
                .distinct()
                .forEach(scanRunService::checkAndCompleteRun);
    }
}
