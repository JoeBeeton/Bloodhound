package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.bucketbrute.BucketBruteForceIngestionService;
import org.freedonia.bloodhound.server.ctmonitor.CtCheckResultService;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.freedonia.bloodhound.server.findings.ResultIngestionService;
import org.freedonia.bloodhound.server.fingerprint.FingerprintIngestionService;
import org.freedonia.bloodhound.server.subdomain.SubdomainIngestionService;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.typosquat.TyposquatIngestionService;
import org.freedonia.bloodhound.server.whois.WhoisIngestionService;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class JobLifecycleServiceTest {

    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanJobAttemptRepository scanJobAttemptRepository = mock(ScanJobAttemptRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ResultIngestionService resultIngestionService = mock(ResultIngestionService.class);
    private final SubdomainIngestionService subdomainIngestionService = mock(SubdomainIngestionService.class);
    private final WhoisIngestionService whoisIngestionService = mock(WhoisIngestionService.class);
    private final CtCheckResultService ctCheckResultService = mock(CtCheckResultService.class);
    private final FingerprintIngestionService fingerprintIngestionService = mock(FingerprintIngestionService.class);
    private final TyposquatIngestionService typosquatIngestionService = mock(TyposquatIngestionService.class);
    private final BucketBruteForceIngestionService bucketBruteForceIngestionService =
            mock(BucketBruteForceIngestionService.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final WorkerRepository workerRepository = mock(WorkerRepository.class);
    private final JobLifecycleService service = new JobLifecycleService(
            scanJobRepository, scanJobAttemptRepository, scanRunService, resultIngestionService,
            subdomainIngestionService, whoisIngestionService, ctCheckResultService, fingerprintIngestionService,
            typosquatIngestionService, bucketBruteForceIngestionService, targetRepository, workerRepository, 5);

    private final UUID jobId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final UUID scanRunId = UUID.randomUUID();
    private final String workerId = "worker-1";

    private ScanJob job(String moduleType) {
        return new ScanJob(
                jobId, scanRunId, targetId, moduleType, "CLAIMED", (short) 0, Instant.now(), workerId, Instant.now(),
                Instant.now().plusSeconds(300), 1, 3, "{}", null, null, Instant.now());
    }

    @Test
    void heartbeat_notOwnedOrNotFound_throws404_neverTouchesWorkerPresence() {
        when(scanJobRepository.heartbeat(jobId, workerId, 5)).thenReturn(false);

        assertThatThrownBy(() -> service.heartbeat(jobId, workerId)).isInstanceOf(ResponseStatusException.class);
        verify(workerRepository, never()).heartbeat(any());
    }

    @Test
    void heartbeat_success_alsoRefreshesWorkerPresence() {
        when(scanJobRepository.heartbeat(jobId, workerId, 5)).thenReturn(true);

        service.heartbeat(jobId, workerId);

        verify(workerRepository).heartbeat(workerId);
    }

    @Test
    void result_jobNotFound_throws404() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.result(jobId, workerId, null, List.of(), Map.of(), List.of()))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void result_notOwnedByThisWorker_throws404_neverIngests() {
        // The vulnerability this test guards: a security review found result() used to fetch the
        // job via the plain, ownership-blind findById and ingest against its targetId BEFORE ever
        // checking that workerId actually held this job's lease - so anyone holding the one
        // shared WORKER_API_KEY could ingest (including an empty findings list, which
        // FindingReconciler treats as "resolve every currently-open finding") against ANY org's
        // job by id, real claim or not. findByIdOwnedByForUpdate returning empty here is exactly
        // what happens for a job that exists but this workerId never claimed (or claimed by a
        // different worker, or already terminal) - ingest must never run in that case.
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.result(jobId, workerId, null, List.of(findingPayload()), Map.of(), List.of()))
                .isInstanceOf(ResponseStatusException.class);
        verify(resultIngestionService, never()).ingest(any(), any(), any(), any(), any());
        verify(scanJobRepository, never()).complete(any(), any(), any());
    }

    @Test
    void result_subdomainEnumModule_routedThroughSubdomainIngestion() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("SUBDOMAIN_ENUM")));
        List<FindingPayload> synthesized = List.of();
        when(subdomainIngestionService.ingestAndSynthesizeFindings(eq(targetId), any(), any())).thenReturn(synthesized);
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(true);

        service.result(jobId, workerId, null, List.of(), Map.of("hostnames", List.of()), List.of());

        verify(subdomainIngestionService).ingestAndSynthesizeFindings(eq(targetId), any(), any());
        verify(whoisIngestionService, never()).ingestAndSynthesizeFindings(any(), any(), any(), any());
        verify(resultIngestionService).ingest(scanRunId, targetId, "SUBDOMAIN_ENUM", null, synthesized);
    }

    @Test
    void result_whoisModule_looksUpTargetHostname_routedThroughWhoisIngestion() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("WHOIS")));
        Target target = new Target(targetId, UUID.randomUUID(), "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true, Instant.now(), null);
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target));
        when(whoisIngestionService.ingestAndSynthesizeFindings(eq(targetId), eq("example.com"), any(), any()))
                .thenReturn(List.of());
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(true);

        service.result(jobId, workerId, null, List.of(), Map.of(), List.of());

        verify(whoisIngestionService).ingestAndSynthesizeFindings(eq(targetId), eq("example.com"), any(), any());
    }

    @Test
    void result_ctCheckModule_handledByCtCheckService_producesNoFindingsOfItsOwn() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("CT_CHECK")));
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(true);
        Map<String, Object> rawMetadata = Map.of("hostnames", List.of("new.example.com"));

        service.result(jobId, workerId, null, List.of(), rawMetadata, List.of());

        verify(ctCheckResultService).handle(targetId, rawMetadata);
        verify(resultIngestionService).ingest(scanRunId, targetId, "CT_CHECK", null, List.of());
    }

    @Test
    void result_techFingerprintModule_ingestedViaFingerprintService() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("TECH_FINGERPRINT")));
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(true);
        Map<String, Object> rawMetadata = Map.of("technologies", List.of());

        service.result(jobId, workerId, null, List.of(), rawMetadata, List.of());

        verify(fingerprintIngestionService).ingest(targetId, rawMetadata);
    }

    @Test
    void result_typosquatModule_ingestedForPersistence_butFindingsListPassedThroughUnmodified() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("TYPOSQUAT_MONITOR")));
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(true);
        FindingPayload payload = findingPayload();
        Map<String, Object> rawMetadata = Map.of("candidates", List.of());

        service.result(jobId, workerId, null, List.of(payload), rawMetadata, List.of());

        verify(typosquatIngestionService).ingest(targetId, rawMetadata);
        verify(resultIngestionService).ingest(scanRunId, targetId, "TYPOSQUAT_MONITOR", null, List.of(payload));
    }

    @Test
    void result_ordinaryModule_findingsPassedThroughUnmodified() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("HTTP_HEADERS")));
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(true);
        FindingPayload payload = findingPayload();

        service.result(jobId, workerId, null, List.of(payload), Map.of(), List.of());

        verify(resultIngestionService).ingest(scanRunId, targetId, "HTTP_HEADERS", null, List.of(payload));
    }

    private FindingPayload findingPayload() {
        return new FindingPayload("RULE_X", "HIGH", "EXPOSURE", "title", "desc", "asset", Map.of());
    }

    @Test
    void result_success_completesAttemptAndClearsWorkerJobAndChecksRunCompletion() {
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("HTTP_HEADERS")));
        when(scanJobRepository.complete(jobId, workerId, "meta")).thenReturn(true);

        service.result(jobId, workerId, "meta", List.of(), Map.of(), List.of("line one", "line two"));

        verify(scanJobAttemptRepository).completeAttempt(jobId, "SUCCESS", null, "line one\nline two");
        verify(workerRepository).clearCurrentJob(workerId, jobId);
        verify(scanRunService).checkAndCompleteRun(scanRunId);
    }

    @Test
    void result_ownershipVerifiedButCompleteStillFails_throws404_doesNotMarkAttemptSuccess() {
        // Defensive path only, not the vulnerability the ownership check above closes: with the
        // row locked (FOR UPDATE) from findByIdOwnedByForUpdate through to complete() in the same
        // transaction, nothing else can change claimed_by/status in between in real usage - this
        // just confirms the code still degrades safely (404, no SUCCESS attempt) if complete()
        // ever returns false anyway.
        when(scanJobRepository.findByIdOwnedByForUpdate(jobId, workerId)).thenReturn(Optional.of(job("HTTP_HEADERS")));
        when(scanJobRepository.complete(jobId, workerId, null)).thenReturn(false);

        assertThatThrownBy(() -> service.result(jobId, workerId, null, List.of(), Map.of(), List.of()))
                .isInstanceOf(ResponseStatusException.class);
        // The job never got marked complete, so its attempt shouldn't be marked SUCCESS either.
        verify(scanJobAttemptRepository, never()).completeAttempt(any(), eq("SUCCESS"), any(), any());
    }

    @Test
    void fail_jobNotFound_throws404() {
        when(scanJobRepository.findById(jobId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.fail(jobId, workerId, "boom", List.of())).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void fail_notOwned_throws404() {
        when(scanJobRepository.findById(jobId)).thenReturn(Optional.of(job("HTTP_HEADERS")));
        when(scanJobRepository.fail(jobId, workerId, "boom")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.fail(jobId, workerId, "boom", List.of())).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void fail_retryable_stillHasAttemptsLeft_statusPending_doesNotCheckRunCompletion() {
        when(scanJobRepository.findById(jobId)).thenReturn(Optional.of(job("HTTP_HEADERS")));
        when(scanJobRepository.fail(jobId, workerId, "boom")).thenReturn(Optional.of("PENDING"));

        service.fail(jobId, workerId, "boom", List.of());

        verify(scanJobAttemptRepository).completeAttempt(jobId, "FAILED", "boom", null);
        verify(workerRepository).clearCurrentJob(workerId, jobId);
        verify(scanRunService, never()).checkAndCompleteRun(any());
    }

    @Test
    void fail_exhaustedRetries_terminalFailed_checksRunCompletion() {
        when(scanJobRepository.findById(jobId)).thenReturn(Optional.of(job("HTTP_HEADERS")));
        when(scanJobRepository.fail(jobId, workerId, "boom")).thenReturn(Optional.of("FAILED"));

        service.fail(jobId, workerId, "boom", List.of());

        verify(scanRunService).checkAndCompleteRun(scanRunId);
    }
}
