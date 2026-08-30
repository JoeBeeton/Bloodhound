package org.freedonia.bloodhound.server.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.jobqueue.ScanJobRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunRepository;
import org.freedonia.bloodhound.server.jobqueue.ScanRunService;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;
import org.freedonia.bloodhound.server.target.dto.UpdateTargetRequest;
import org.junit.jupiter.api.Test;

/**
 * notes is the one UpdateTargetRequest field that doesn't follow the plain "null = leave
 * unchanged" convention scanCadenceSeconds/isActive use - a blank string is a deliberate clear,
 * not a no-op, since a saved empty textarea and "field omitted entirely" need to mean the same
 * thing to the caller but arrive as different Java values (a real request always sends the
 * current text, blank included; only a request that isn't touching notes at all - e.g. the
 * Remove/Restore toggle - omits the field and gets Java null).
 */
class TargetControllerUpdateTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScanRunService scanRunService = mock(ScanRunService.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final ScanRunRepository scanRunRepository = mock(ScanRunRepository.class);
    private final ScanJobRepository scanJobRepository = mock(ScanJobRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final TargetController controller = new TargetController(
            targetRepository, scanRunService, scoreSnapshotRepository, scanRunRepository, scanJobRepository, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private Target target(String notes) {
        return target(notes, true);
    }

    private Target target(String notes, boolean isActive) {
        return new Target(
                targetId, orgId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), isActive, Instant.now(), notes);
    }

    @Test
    void update_notesOmitted_leavesNotesUntouched() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("existing note")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("existing note")));

        controller.update(targetId, new UpdateTargetRequest(null, false, null), admin);

        verify(targetRepository, never()).updateNotes(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void update_blankNotes_clearsNotes() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target("existing note")));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target(null)));

        controller.update(targetId, new UpdateTargetRequest(null, null, ""), admin);

        verify(targetRepository).updateNotes(targetId, "");
    }

    @Test
    void update_nonBlankNotes_setsNotes() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(null)));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target("staging environment, owned by platform team")));

        TargetSummary result =
                controller.update(targetId, new UpdateTargetRequest(null, null, "staging environment, owned by platform team"), admin);

        verify(targetRepository).updateNotes(targetId, "staging environment, owned by platform team");
        assertThat(result.notes()).isEqualTo("staging environment, owned by platform team");
    }

    @Test
    void update_cadenceAndActiveStillPassThrough_alongsideNotes() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(null)));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target(null)));

        controller.update(targetId, new UpdateTargetRequest(7200, true, null), admin);

        verify(targetRepository).updateCadenceAndActive(targetId, 7200, true);
    }

    @Test
    void update_activeFlippedToFalse_recordsTargetRemoved() {
        // A reliability review found this the only sensitive state change in TargetController not
        // audited - "Remove" pauses monitoring org-wide with no trail of who did it or when.
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(null, true)));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target(null, false)));

        controller.update(targetId, new UpdateTargetRequest(null, false, null), admin);

        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "TARGET_REMOVED", "TARGET", targetId.toString(), "hostname=example.com");
    }

    @Test
    void update_activeFlippedToTrue_recordsTargetRestored() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(null, false)));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target(null, true)));

        controller.update(targetId, new UpdateTargetRequest(null, true, null), admin);

        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "TARGET_RESTORED", "TARGET", targetId.toString(), "hostname=example.com");
    }

    @Test
    void update_activeUnchanged_doesNotRecordAudit() {
        // Re-sending the same isActive value (e.g. a cadence-only edit that happens to also
        // include the current isActive) isn't a real state transition - nothing for an admin to
        // investigate, so nothing should land in the audit log.
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(null, true)));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target(null, true)));

        controller.update(targetId, new UpdateTargetRequest(null, true, null), admin);

        verify(auditLogRepository, never())
                .record(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any());
    }

    @Test
    void update_activeOmitted_cadenceOrNotesOnlyEdit_doesNotRecordAudit() {
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target(null, true)));
        when(targetRepository.findById(targetId)).thenReturn(Optional.of(target(null, true)));

        controller.update(targetId, new UpdateTargetRequest(7200, null, "a note"), admin);

        verify(auditLogRepository, never())
                .record(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any());
    }
}
