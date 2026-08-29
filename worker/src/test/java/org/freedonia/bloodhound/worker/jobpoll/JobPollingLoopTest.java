package org.freedonia.bloodhound.worker.jobpoll;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.jobpoll.dto.ClaimedJob;
import org.freedonia.bloodhound.worker.jobpoll.dto.ClaimRequest;
import org.freedonia.bloodhound.worker.jobpoll.dto.FailRequest;
import org.freedonia.bloodhound.worker.jobpoll.dto.ResultRequest;
import org.freedonia.bloodhound.worker.modules.ScanModuleRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

/**
 * The dispatch loop's branching: module-not-found, success, expected
 * ScanModuleException, and unexpected exception all report a different
 * outcome back to central-server, and the heartbeat is always started before
 * dispatch and stopped afterward regardless of which path is taken.
 *
 * <p>RestClient's fluent builder is mocked step-by-step. {@code .uri(...)} is
 * intentionally NOT disambiguated by its arguments here (RestClient.UriSpec's
 * only String-based overload is {@code uri(String, Object...)}, so the
 * zero-vararg claim call and the one-vararg result/fail calls are actually
 * the same overloaded method with different array lengths - fragile to
 * distinguish via separate stubs). Instead every {@code .uri(...)} call
 * returns one shared {@code RequestBodySpec}, and the three request shapes
 * (ClaimRequest vs FailRequest vs ResultRequest) are disambiguated by the
 * type passed to {@code .body(...)}, which is an ordinary overloaded method
 * Mockito matches cleanly - and is arguably the more meaningful thing to
 * assert on anyway, since it verifies the actual payload sent.
 */
class JobPollingLoopTest {

    private final RestClient centralServerClient = mock(RestClient.class);
    private final JobHeartbeatSender heartbeatSender = mock(JobHeartbeatSender.class);
    private final JobHeartbeatSender.Handle heartbeatHandle = mock(JobHeartbeatSender.Handle.class);
    private final RestClient.RequestBodyUriSpec uriSpec = mock(RestClient.RequestBodyUriSpec.class);
    private final RestClient.RequestBodySpec preBodySpec = mock(RestClient.RequestBodySpec.class);
    private final RestClient.RequestBodySpec claimBodySpec = mock(RestClient.RequestBodySpec.class);
    private final RestClient.ResponseSpec claimResponseSpec = mock(RestClient.ResponseSpec.class);
    private final RestClient.RequestBodySpec reportBodySpec = mock(RestClient.RequestBodySpec.class);
    private final RestClient.ResponseSpec reportResponseSpec = mock(RestClient.ResponseSpec.class);

    private final UUID targetId = UUID.randomUUID();
    private final UUID jobId = UUID.randomUUID();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void wireCommonStubs() {
        when(centralServerClient.post()).thenReturn(uriSpec);
        when(heartbeatSender.start(any())).thenReturn(heartbeatHandle);
        when(uriSpec.uri(any(String.class))).thenReturn(preBodySpec);
        when(uriSpec.uri(any(String.class), any(Object.class))).thenReturn(preBodySpec);

        when(preBodySpec.body(any(ClaimRequest.class))).thenReturn(claimBodySpec);
        when(claimBodySpec.retrieve()).thenReturn(claimResponseSpec);

        when(preBodySpec.body(any(FailRequest.class))).thenReturn(reportBodySpec);
        when(preBodySpec.body(any(ResultRequest.class))).thenReturn(reportBodySpec);
        when(reportBodySpec.retrieve()).thenReturn(reportResponseSpec);
        when(reportResponseSpec.toBodilessEntity()).thenReturn(ResponseEntity.ok().build());
    }

    private JobPollingLoop loop(ScanModule... modules) {
        ScanModuleRegistry registry = new ScanModuleRegistry(List.of(modules));
        return new JobPollingLoop(centralServerClient, registry, heartbeatSender, "worker-1", 1);
    }

    @SuppressWarnings("unchecked")
    private void stubClaimReturns(List<ClaimedJob> jobs) {
        when(claimResponseSpec.body(any(ParameterizedTypeReference.class))).thenReturn(jobs);
    }

    @SuppressWarnings("unchecked")
    private void stubClaimThrows(RuntimeException e) {
        when(claimResponseSpec.body(any(ParameterizedTypeReference.class))).thenThrow(e);
    }

    private ClaimedJob claimedJob(String moduleType) {
        return new ClaimedJob(jobId, targetId, "example.com", UUID.randomUUID(), moduleType, Map.of());
    }

    @Test
    void claimThrows_pollReturnsQuietly_noHeartbeatStarted() {
        stubClaimThrows(new RuntimeException("connection refused"));

        loop().poll();

        verify(heartbeatSender, never()).start(any());
    }

    @Test
    void claimReturnsNull_pollReturnsQuietly() {
        stubClaimReturns(null);

        loop().poll();

        verify(heartbeatSender, never()).start(any());
    }

    @Test
    void claimReturnsEmptyList_pollReturnsQuietly() {
        stubClaimReturns(List.of());

        loop().poll();

        verify(heartbeatSender, never()).start(any());
    }

    @Test
    void moduleNotRegistered_reportsFailure_neverStartsHeartbeat() {
        stubClaimReturns(List.of(claimedJob("UNKNOWN_MODULE")));

        loop().poll();

        verify(heartbeatSender, never()).start(any());
        verify(preBodySpec)
                .body(argThat((Object arg) -> arg instanceof FailRequest fr
                        && fr.errorDetail().contains("no worker module registered")));
    }

    @FunctionalInterface
    private interface Execution {
        ModuleResult execute(ScanContext context) throws ScanModuleException;
    }

    @Test
    void successfulExecution_reportsResult_startsAndStopsHeartbeat() {
        ScanModule module = fakeModule("DNS_POSTURE", ctx -> new ModuleResult(
                List.of(new RawFinding(
                        "DNS_SPF_MISSING", Severity.MEDIUM, Category.DNS, "title", "desc", "example.com", Map.of())),
                Map.of("checked", true)));
        stubClaimReturns(List.of(claimedJob("DNS_POSTURE")));

        loop(module).poll();

        verify(heartbeatSender).start(jobId);
        verify(heartbeatHandle).stop();
        verify(preBodySpec).body(argThat((Object arg) -> arg instanceof ResultRequest rr
                && rr.findings().size() == 1
                && "DNS_SPF_MISSING".equals(rr.findings().get(0).ruleId())));
    }

    @Test
    void moduleThrowsScanModuleException_reportsFailureWithMessage_stillStopsHeartbeat() {
        ScanModule module = fakeModule("DNS_POSTURE", ctx -> {
            throw new ScanModuleException("dns lookup timed out");
        });
        stubClaimReturns(List.of(claimedJob("DNS_POSTURE")));

        loop(module).poll();

        verify(heartbeatSender).start(jobId);
        verify(heartbeatHandle).stop();
        verify(preBodySpec)
                .body(argThat((Object arg) -> arg instanceof FailRequest fr && "dns lookup timed out".equals(fr.errorDetail())));
    }

    @Test
    void moduleThrowsScanModuleExceptionWithCause_reportsFailureIncludingCauseDetail() {
        // The bare outer message alone (e.g. "failed to reach ZAP at ...") was previously the
        // ONLY thing that reached error_detail/the UI - the actual wire-level cause (connection
        // refused vs. a timeout vs. something else) was silently dropped, making a real,
        // diagnosable failure indistinguishable from any other. See withCause's own javadoc.
        ScanModule module = fakeModule("ZAP_ACTIVE_SCAN", ctx -> {
            throw new ScanModuleException(
                    "failed to reach ZAP at http://zap:8080/JSON/core/view/numberOfMessages/",
                    new java.io.IOException("request timed out"));
        });
        stubClaimReturns(List.of(claimedJob("ZAP_ACTIVE_SCAN")));

        loop(module).poll();

        verify(preBodySpec)
                .body(argThat((Object arg) -> arg instanceof FailRequest fr
                        && fr.errorDetail().contains("failed to reach ZAP")
                        && fr.errorDetail().contains("IOException")
                        && fr.errorDetail().contains("request timed out")));
    }

    @Test
    void moduleThrowsUnexpectedException_reportsFailureWithWrappedMessage_stillStopsHeartbeat() {
        ScanModule module = fakeModule("DNS_POSTURE", ctx -> {
            throw new IllegalStateException("boom");
        });
        stubClaimReturns(List.of(claimedJob("DNS_POSTURE")));

        loop(module).poll();

        verify(heartbeatHandle).stop();
        verify(preBodySpec)
                .body(argThat((Object arg) -> arg instanceof FailRequest fr
                        && fr.errorDetail().contains("unexpected error")
                        && fr.errorDetail().contains("boom")));
    }

    @Test
    void multipleClaimedJobs_executedSequentially_eachReportedIndependently() {
        UUID secondJobId = UUID.randomUUID();
        ClaimedJob first = claimedJob("DNS_POSTURE");
        ClaimedJob second =
                new ClaimedJob(secondJobId, targetId, "example.com", UUID.randomUUID(), "DNS_POSTURE", Map.of());
        stubClaimReturns(List.of(first, second));
        ScanModule module = fakeModule("DNS_POSTURE", ctx -> new ModuleResult(List.of(), Map.of()));

        loop(module).poll();

        verify(heartbeatSender, times(1)).start(jobId);
        verify(heartbeatSender, times(1)).start(secondJobId);
        verify(heartbeatHandle, times(2)).stop();
    }

    private ScanModule fakeModule(String moduleType, Execution execution) {
        return new ScanModule() {
            @Override
            public String moduleType() {
                return moduleType;
            }

            @Override
            public ScanTier tier() {
                return ScanTier.TIER_1;
            }

            @Override
            public ModuleResult execute(ScanContext context) throws ScanModuleException {
                return execution.execute(context);
            }
        };
    }
}
