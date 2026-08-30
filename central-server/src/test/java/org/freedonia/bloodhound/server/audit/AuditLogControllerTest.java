package org.freedonia.bloodhound.server.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class AuditLogControllerTest {

    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final AuditLogController controller = new AuditLogController(auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID otherOrgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private AuditLogEntry entry() {
        return new AuditLogEntry(
                UUID.randomUUID(), orgId, admin.userId(), admin.email(), "TARGET_DELETED", "TARGET", "id", "hostname=x", Instant.now());
    }

    @Test
    void list_orgIdMismatch_forbidden() {
        assertThatThrownBy(() -> controller.list(otherOrgId, 50, 0, admin)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void list_matchingOrg_returnsPageWithTotalCountHeader() {
        when(auditLogRepository.findByOrganization(orgId, 50, 0)).thenReturn(List.of(entry()));
        when(auditLogRepository.countByOrganization(orgId)).thenReturn(1);

        ResponseEntity<List<AuditLogEntry>> response = controller.list(orgId, 50, 0, admin);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("X-Total-Count")).isEqualTo("1");
        assertThat(response.getBody()).hasSize(1);
    }

    @Test
    void list_limitClampedToMax200() {
        when(auditLogRepository.findByOrganization(eq(orgId), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(orgId, 999999, 0, admin);

        org.mockito.Mockito.verify(auditLogRepository).findByOrganization(orgId, 200, 0);
    }

    @Test
    void list_negativeOffsetClampedToZero() {
        when(auditLogRepository.findByOrganization(eq(orgId), anyInt(), anyInt())).thenReturn(List.of());

        controller.list(orgId, 50, -5, admin);

        org.mockito.Mockito.verify(auditLogRepository).findByOrganization(orgId, 50, 0);
    }
}
