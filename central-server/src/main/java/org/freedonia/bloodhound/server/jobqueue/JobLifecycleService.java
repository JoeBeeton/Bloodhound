package org.freedonia.bloodhound.server.jobqueue;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.bucketbrute.BucketBruteForceIngestionService;
import org.freedonia.bloodhound.server.ctmonitor.CtCheckResultService;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.freedonia.bloodhound.server.findings.ResultIngestionService;
import org.freedonia.bloodhound.server.fingerprint.FingerprintIngestionService;
import org.freedonia.bloodhound.server.subdomain.SubdomainIngestionService;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.typosquat.TyposquatIngestionService;
import org.freedonia.bloodhound.server.whois.WhoisIngestionService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Heartbeat/result/fail reporting for a job a worker currently holds the lease on. */
@Service
public class JobLifecycleService {

    private final ScanJobRepository scanJobRepository;
    private final ScanJobAttemptRepository scanJobAttemptRepository;
    private final ScanRunService scanRunService;
    private final ResultIngestionService resultIngestionService;
    private final SubdomainIngestionService subdomainIngestionService;
    private final WhoisIngestionService whoisIngestionService;
    private final CtCheckResultService ctCheckResultService;
    private final FingerprintIngestionService fingerprintIngestionService;
    private final TyposquatIngestionService typosquatIngestionService;
    private final BucketBruteForceIngestionService bucketBruteForceIngestionService;
    private final TargetRepository targetRepository;
    private final WorkerRepository workerRepository;
    private final int leaseMinutes;

    public JobLifecycleService(
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            ScanRunService scanRunService,
            ResultIngestionService resultIngestionService,
            SubdomainIngestionService subdomainIngestionService,
            WhoisIngestionService whoisIngestionService,
            CtCheckResultService ctCheckResultService,
            FingerprintIngestionService fingerprintIngestionService,
            TyposquatIngestionService typosquatIngestionService,
            BucketBruteForceIngestionService bucketBruteForceIngestionService,
            TargetRepository targetRepository,
            WorkerRepository workerRepository,
            @Value("${bloodhound.jobqueue.lease-minutes:5}") int leaseMinutes) {
        this.scanJobRepository = scanJobRepository;
        this.scanJobAttemptRepository = scanJobAttemptRepository;
        this.scanRunService = scanRunService;
        this.resultIngestionService = resultIngestionService;
        this.subdomainIngestionService = subdomainIngestionService;
        this.whoisIngestionService = whoisIngestionService;
        this.ctCheckResultService = ctCheckResultService;
        this.fingerprintIngestionService = fingerprintIngestionService;
        this.typosquatIngestionService = typosquatIngestionService;
        this.bucketBruteForceIngestionService = bucketBruteForceIngestionService;
        this.targetRepository = targetRepository;
        this.workerRepository = workerRepository;
        this.leaseMinutes = leaseMinutes;
    }

    public void heartbeat(UUID jobId, String workerId) {
        if (!scanJobRepository.heartbeat(jobId, workerId, leaseMinutes)) {
            throw notFoundOrNotOwned();
        }
        // A worker busy on one long-running module (ZAP's active scan can run for many
        // minutes) doesn't call /jobs/claim again until that job finishes - see
        // JobPollingLoop's sequential-dispatch doc comment - so relying on the claim
        // endpoint alone for presence would flip a genuinely-alive, genuinely-working
        // worker to OFFLINE mid-scan. JobHeartbeatSender already pings this endpoint
        // periodically for exactly this kind of long job, so refreshing presence here
        // too keeps a busy worker correctly online for as long as it's actually working.
        workerRepository.heartbeat(workerId);
    }

    /**
     * A security review found this previously fetched the job via the plain, ownership-blind
     * {@code findById} and ingested its findings/subdomains/fingerprints before ever checking
     * that {@code workerId} actually held this job's lease - the claimed_by/status check only
     * happened at the very end, via {@code complete}, by which point the ingest had already run.
     * Since workerId is caller-supplied and every worker shares one WORKER_API_KEY, anyone
     * holding the key could ingest (including an empty findings list, which FindingReconciler
     * treats as "resolve every currently-open finding") against ANY org's job by id, real claim
     * or not. {@code @Transactional} + {@link ScanJobRepository#findByIdOwnedByForUpdate} moves
     * the ownership check to the very first thing that happens, and holds the row lock for the
     * rest of this method so nothing else can change the job's claim state mid-ingest.
     */
    @Transactional
    public void result(
            UUID jobId,
            String workerId,
            String resultMetadataJson,
            List<FindingPayload> findings,
            Map<String, Object> rawMetadata,
            List<String> logLines) {
        ScanJob job = scanJobRepository
                .findByIdOwnedByForUpdate(jobId, workerId)
                .orElseThrow(JobLifecycleService::notFoundOrNotOwned);
        // SUBDOMAIN_ENUM and WHOIS are the module types whose results need
        // more than the generic findings-reconciliation path: each carries
        // rawMetadata that only makes sense against this target's history
        // (is this hostname new? did the registrar change?), which only
        // central-server's DB can answer - see SubdomainIngestionService /
        // WhoisIngestionService. CT_CHECK needs even less: it produces no
        // findings of its own at all, just a hostname list to diff against
        // the subdomains table - see CtCheckResultService, which may react
        // by enqueuing a full CT_TRIGGERED rescan but never touches this
        // job's own findings/completion path. TECH_FINGERPRINT is the same
        // shape as SUBDOMAIN_ENUM/WHOIS: a stateless worker module hands back
        // structured per-hostname data via rawMetadata, persisted here into
        // the fingerprints table - it emits no findings of its own.
        // TYPOSQUAT_MONITOR is stateless too and also hands back structured
        // data via rawMetadata (the full checked-candidate list, persisted
        // into typosquat_candidates), but - unlike TECH_FINGERPRINT - it DOES
        // emit its own findings via the normal list, since "is this candidate
        // registered" needs no target history to decide. BUCKET_BRUTE_FORCE
        // is the identical shape: stateless, emits its own findings via the
        // normal list, and separately persists every (candidate, provider)
        // it checked into bucket_brute_force_checks purely so the *next*
        // deep scan's job payload can exclude names already tried recently
        // (see ScanRunService#createDeepScan). Every other module type's
        // rawMetadata is ignored here.
        List<FindingPayload> effectiveFindings;
        if ("SUBDOMAIN_ENUM".equals(job.moduleType())) {
            effectiveFindings = subdomainIngestionService.ingestAndSynthesizeFindings(job.targetId(), rawMetadata, findings);
        } else if ("WHOIS".equals(job.moduleType())) {
            String hostname = targetRepository
                    .findById(job.targetId())
                    .map(org.freedonia.bloodhound.server.target.Target::hostname)
                    .orElse(null);
            effectiveFindings =
                    whoisIngestionService.ingestAndSynthesizeFindings(job.targetId(), hostname, rawMetadata, findings);
        } else if ("CT_CHECK".equals(job.moduleType())) {
            ctCheckResultService.handle(job.targetId(), rawMetadata);
            effectiveFindings = findings;
        } else if ("TECH_FINGERPRINT".equals(job.moduleType())) {
            fingerprintIngestionService.ingest(job.targetId(), rawMetadata);
            effectiveFindings = findings;
        } else if ("TYPOSQUAT_MONITOR".equals(job.moduleType())) {
            // Same shape as TECH_FINGERPRINT: the module is stateless and already
            // emits TYPOSQUAT_DOMAIN_REGISTERED via the normal findings list itself
            // (registration status is knowable within one scan, no target history
            // needed) - this call is purely for its side effect of persisting the
            // full checked-candidate list into typosquat_candidates.
            typosquatIngestionService.ingest(job.targetId(), rawMetadata);
            effectiveFindings = findings;
        } else if ("BUCKET_BRUTE_FORCE".equals(job.moduleType())) {
            bucketBruteForceIngestionService.ingest(job.targetId(), rawMetadata);
            effectiveFindings = findings;
        } else {
            effectiveFindings = findings;
        }
        // Ingest before marking complete: if reconciliation throws, the job
        // stays CLAIMED/RUNNING and the lease reaper will retry it, rather
        // than silently completing a job whose findings never landed.
        //
        // The scope is the per-host job's own host (null for every whole-target job): a
        // NUCLEI_SCAN job for host A must only reconcile against host A's open findings, or it
        // resolves every sibling host's findings on the way through - the Tier 2 flapping bug
        // described in V53__findings_scan_scope.sql.
        resultIngestionService.ingest(
                job.scanRunId(),
                job.targetId(),
                job.moduleType(),
                JobPayloadHost.extract(job.payloadJson()),
                effectiveFindings);
        if (!scanJobRepository.complete(jobId, workerId, resultMetadataJson)) {
            throw notFoundOrNotOwned();
        }
        scanJobAttemptRepository.completeAttempt(jobId, "SUCCESS", null, joinLogLines(logLines));
        workerRepository.clearCurrentJob(workerId, jobId);
        scanRunService.checkAndCompleteRun(job.scanRunId());
    }

    public void fail(UUID jobId, String workerId, String errorDetail, List<String> logLines) {
        ScanJob job = scanJobRepository.findById(jobId).orElseThrow(JobLifecycleService::notFoundOrNotOwned);
        String newStatus =
                scanJobRepository.fail(jobId, workerId, errorDetail).orElseThrow(JobLifecycleService::notFoundOrNotOwned);
        // The attempt itself failed either way - whether the job as a whole is now retrying
        // (PENDING) or terminal (FAILED) is a separate question from what happened to *this* try.
        scanJobAttemptRepository.completeAttempt(jobId, "FAILED", errorDetail, joinLogLines(logLines));
        // The worker is done with this attempt regardless of whether the job itself is
        // now retrying (PENDING, no owner) or terminal (FAILED) - either way it's no
        // longer *this* worker's current job.
        workerRepository.clearCurrentJob(workerId, jobId);
        if ("FAILED".equals(newStatus)) {
            scanRunService.checkAndCompleteRun(job.scanRunId());
        }
    }

    /** null (not an empty string) when there's nothing captured, so the UI can tell "no log output" from "a genuinely empty log" and skip rendering the section entirely. */
    private static String joinLogLines(List<String> logLines) {
        if (logLines == null || logLines.isEmpty()) {
            return null;
        }
        return String.join("\n", logLines);
    }

    private static ResponseStatusException notFoundOrNotOwned() {
        return new ResponseStatusException(
                HttpStatus.NOT_FOUND, "job not found, not claimed by this worker, or already terminal");
    }
}
