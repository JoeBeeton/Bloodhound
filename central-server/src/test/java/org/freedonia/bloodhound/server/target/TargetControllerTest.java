package org.freedonia.bloodhound.server.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanJobAttemptRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.dto.BulkCreateTargetsRequest;
import org.freedonia.bloodhound.server.target.dto.CreateTargetRequest;
import org.freedonia.bloodhound.server.target.dto.UpdateTargetRequest;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class TargetControllerTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final ScanJobAttemptRepository scanJobAttemptRepository = mock(ScanJobAttemptRepository.class);
    private final TargetAuthorizationRepository targetAuthorizationRepository = mock(TargetAuthorizationRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    // Real, not mocked - same reasoning ApiKeyRateLimiterTest/ApiKeyAuthFilterTest use for their
    // own sibling limiter: a simple, deterministic, no-dependency component. JUnit 5's default
    // per-method test instance lifecycle gives every @Test its own fresh instance (same as admin's
    // own random UUID below), so this never accumulates state across tests.
    private final TargetBulkCreateRateLimiter targetBulkCreateRateLimiter = new TargetBulkCreateRateLimiter();
    private final FindingRepository findingRepository = mock(FindingRepository.class);

    {
        when(findingRepository.findWafStatusByTarget(any())).thenReturn(Map.of());
        when(scanJobAttemptRepository.averageSecondsByModuleType(anyInt())).thenReturn(Map.of());
    }

    private TargetController controller(int maxTargetsPerOrg) {
        return new TargetController(
                targetRepository,
                scanRunService,
                scoreSnapshotRepository,
                scanRunRepository,
                scanJobRepository,
                scanJobAttemptRepository,
                targetAuthorizationRepository,
                auditLogRepository,
                targetBulkCreateRateLimiter,
                findingRepository,
                maxTargetsPerOrg);
    }

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private Target target(UUID id, String hostname) {
        return new Target(id, orgId, hostname, "OWN", "UNAUTHORIZED", 86400, Instant.now(), true, Instant.now(), null);
    }

    @Test
    void create_atCap_rejected_neverInserts() {
        TargetController controller = controller(5);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(5);

        assertThatThrownBy(() -> controller.create(new CreateTargetRequest("example.com", "OWN"), admin))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(409));
        verify(targetRepository, never()).insert(any(), anyString(), anyString());
    }

    @Test
    void create_underCap_succeeds() {
        TargetController controller = controller(5);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(4);
        UUID id = UUID.randomUUID();
        when(targetRepository.insert(orgId, "example.com", "OWN")).thenReturn(target(id, "example.com"));

        ResponseEntity<?> response = controller.create(new CreateTargetRequest("example.com", "OWN"), admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
    }

    @Test
    void createBulk_mixedBatch_eachHostnameGetsItsOwnResult() {
        TargetController controller = controller(100);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(0);
        when(targetRepository.insert(orgId, "good.example.com", "OWN"))
                .thenReturn(target(UUID.randomUUID(), "good.example.com"));
        when(targetRepository.insert(orgId, "dupe.example.com", "OWN")).thenThrow(new DataIntegrityViolationException("dup"));

        ResponseEntity<?> response = controller.createBulk(
                new BulkCreateTargetsRequest(
                        List.of("good.example.com", "dupe.example.com", "not a valid hostname", "127.0.0.1", "  "),
                        "OWN"),
                admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        @SuppressWarnings("unchecked")
        List<TargetController.BulkCreateTargetResult> results =
                (List<TargetController.BulkCreateTargetResult>) response.getBody();
        // The blank line is silently dropped, not reported as a failure - not a hostname a caller
        // pasted intending to track, just whitespace between real lines.
        assertThat(results).hasSize(4);

        assertThat(results.get(0).hostname()).isEqualTo("good.example.com");
        assertThat(results.get(0).created()).isTrue();

        assertThat(results.get(1).hostname()).isEqualTo("dupe.example.com");
        assertThat(results.get(1).created()).isFalse();
        assertThat(results.get(1).error()).contains("already tracked");

        assertThat(results.get(2).hostname()).isEqualTo("not a valid hostname");
        assertThat(results.get(2).created()).isFalse();
        assertThat(results.get(2).error()).contains("valid domain name");

        // An IP literal in loopback range - the same SSRF guard create() applies via
        // rejectUnsafeHostname, exercised here through its shared underlying check.
        // requireSafeIfResolvable recognizes IP literals directly with no DNS resolution needed,
        // so this is deterministic in a unit test unlike a real hostname would be.
        assertThat(results.get(3).hostname()).isEqualTo("127.0.0.1");
        assertThat(results.get(3).created()).isFalse();
        assertThat(results.get(3).error()).contains("private, loopback, or reserved");
    }

    @Test
    void createBulk_stopsCountingAgainstCapOnceReached_restMarkedAsCapExceeded() {
        TargetController controller = controller(2);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(0);
        when(targetRepository.insert(any(), anyString(), anyString()))
                .thenAnswer(inv -> target(UUID.randomUUID(), inv.getArgument(1)));

        ResponseEntity<?> response = controller.createBulk(
                new BulkCreateTargetsRequest(List.of("a.example.com", "b.example.com", "c.example.com"), "OWN"), admin);

        @SuppressWarnings("unchecked")
        List<TargetController.BulkCreateTargetResult> results =
                (List<TargetController.BulkCreateTargetResult>) response.getBody();
        assertThat(results.get(0).created()).isTrue();
        assertThat(results.get(1).created()).isTrue();
        assertThat(results.get(2).created()).isFalse();
        assertThat(results.get(2).error()).contains("reached its limit");
        verify(targetRepository, never()).insert(orgId, "c.example.com", "OWN");
    }

    @Test
    void createBulk_recordsOneAuditEntryWithTheCreatedCount_notPerHostname() {
        TargetController controller = controller(100);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(0);
        when(targetRepository.insert(any(), anyString(), anyString()))
                .thenAnswer(inv -> target(UUID.randomUUID(), inv.getArgument(1)));

        controller.createBulk(new BulkCreateTargetsRequest(List.of("a.example.com", "b.example.com"), "OWN"), admin);

        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "TARGETS_BULK_CREATED", "ORGANIZATION", orgId.toString(), "count=2");
    }

    @Test
    void createBulk_nothingCreated_neverRecordsAudit() {
        TargetController controller = controller(100);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(0);

        controller.createBulk(new BulkCreateTargetsRequest(List.of("not a valid hostname"), "OWN"), admin);

        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createBulk_callerOverItsRateLimit_returns429_neverTouchesTheRepository() {
        // A security review found this endpoint had no limit on how often it could be called at
        // all - each call runs a real synchronous DNS lookup per hostname, up to 100 per request,
        // so unbounded repeated calls meant unbounded outbound DNS traffic at zero cost to the
        // caller.
        TargetController controller = controller(100);
        for (int i = 0; i < 10; i++) {
            targetBulkCreateRateLimiter.recordRequest(admin.userId());
        }

        ResponseEntity<?> response =
                controller.createBulk(new BulkCreateTargetsRequest(List.of("example.com"), "OWN"), admin);

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getHeaders().getFirst("Retry-After")).isNotNull();
        verify(targetRepository, never()).countActiveByOrganization(any());
        verify(targetRepository, never()).insert(any(), anyString(), anyString());
    }

    @Test
    void createBulk_callerUnderItsRateLimit_stillProcessesNormally() {
        TargetController controller = controller(100);
        when(targetRepository.countActiveByOrganization(orgId)).thenReturn(0);
        when(targetRepository.insert(orgId, "example.com", "OWN")).thenReturn(target(UUID.randomUUID(), "example.com"));
        for (int i = 0; i < 9; i++) {
            targetBulkCreateRateLimiter.recordRequest(admin.userId());
        }

        ResponseEntity<?> response =
                controller.createBulk(new BulkCreateTargetsRequest(List.of("example.com"), "OWN"), admin);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
    }

    @Test
    void update_retypingAwayFromOwn_revokesAuthorizationAndCancelsQueuedTier2Jobs() {
        // A security review found "authorize as OWN, then PATCH the type to COMPETITOR" revoked
        // authorization_status (already covered elsewhere) but left any already-queued deep-scan
        // jobs sitting in the queue unchanged - they would still get claimed and run.
        UUID targetId = UUID.randomUUID();
        Target before = target(targetId, "example.com");
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(java.util.Optional.of(before));
        when(targetRepository.findById(targetId)).thenReturn(java.util.Optional.of(before));

        controller(100).update(targetId, new UpdateTargetRequest(null, null, null, "COMPETITOR"), admin);

        verify(targetAuthorizationRepository).revokeCurrent(targetId, admin.userId());
        verify(scanJobRepository).cancelNonTerminalTier2ForTarget(targetId, ScanRunService.allTier2ModuleTypes());
    }

    @Test
    void update_retypingButStayingOwn_doesNotRevokeOrCancelAnything() {
        UUID targetId = UUID.randomUUID();
        Target before = target(targetId, "example.com");
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(java.util.Optional.of(before));
        when(targetRepository.findById(targetId)).thenReturn(java.util.Optional.of(before));

        controller(100).update(targetId, new UpdateTargetRequest(null, null, null, "OWN"), admin);

        verify(targetAuthorizationRepository, never()).revokeCurrent(any(), any());
        verify(scanJobRepository, never()).cancelNonTerminalTier2ForTarget(any(), any());
    }
}
