package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class McpConnectionsControllerTest {

    private final McpConnectionRepository connectionRepository = mock(McpConnectionRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final McpConnectionsController controller =
            new McpConnectionsController(connectionRepository, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID otherOrgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    @Test
    void list_differentOrg_notFound() {
        assertThatThrownBy(() -> controller.list(otherOrgId, admin)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void list_ownOrg_returnsMappedConnections() {
        McpConnection conn = new McpConnection(
                "client-1", "Claude Desktop", "user@example.com", List.of("mcp.read"), Instant.now(), Instant.now());
        when(connectionRepository.findByOrganization(orgId)).thenReturn(List.of(conn));

        var result = controller.list(orgId, admin);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).registeredClientId()).isEqualTo("client-1");
        assertThat(result.get(0).clientName()).isEqualTo("Claude Desktop");
        assertThat(result.get(0).principalEmail()).isEqualTo("user@example.com");
        assertThat(result.get(0).scopes()).containsExactly("mcp.read");
    }

    @Test
    void revoke_differentOrg_notFound_neverDeletes() {
        assertThatThrownBy(() -> controller.revoke(otherOrgId, "client-1", "user@example.com", admin))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void revoke_nothingMatched_notFound_noAuditEntry() {
        when(connectionRepository.revoke(orgId, "client-1", "user@example.com")).thenReturn(0);

        assertThatThrownBy(() -> controller.revoke(orgId, "client-1", "user@example.com", admin))
                .isInstanceOf(ResponseStatusException.class);
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
    void revoke_matched_returnsNoContent_recordsAuditEntry() {
        when(connectionRepository.revoke(orgId, "client-1", "user@example.com")).thenReturn(1);

        var response = controller.revoke(orgId, "client-1", "user@example.com", admin);

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(auditLogRepository)
                .record(
                        orgId,
                        admin.userId(),
                        admin.email(),
                        "MCP_CONNECTION_REVOKED",
                        "MCP_CLIENT",
                        "client-1",
                        "user=user@example.com");
    }
}
