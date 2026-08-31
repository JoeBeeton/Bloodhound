package org.freedonia.bloodhound.server.mcp;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Lists and revokes which AI-agent (MCP) clients have been authorized against this org's data,
 * and by which user - see McpConnectionRepository for why this reads oauth2_authorization
 * directly rather than the schema's (unused, in-memory-only) oauth2_authorization_consent table.
 *
 * <p>A product review found the org-wide MCP kill switch on OrganizationSettingsController was
 * the *only* control that existed: an admin had no way to even see which clients had connected,
 * let alone revoke just one without kicking every other connected agent off too. This is the
 * scalpel next to that hammer.
 */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/mcp/connections")
@PreAuthorize("hasRole('ADMIN')")
public class McpConnectionsController {

    private final McpConnectionRepository connectionRepository;
    private final AuditLogRepository auditLogRepository;

    public McpConnectionsController(
            McpConnectionRepository connectionRepository, AuditLogRepository auditLogRepository) {
        this.connectionRepository = connectionRepository;
        this.auditLogRepository = auditLogRepository;
    }

    public record McpConnectionResponse(
            String registeredClientId,
            String clientName,
            String principalEmail,
            List<String> scopes,
            Instant lastActiveAt,
            Instant refreshTokenExpiresAt) {
        static McpConnectionResponse from(McpConnection c) {
            return new McpConnectionResponse(
                    c.registeredClientId(),
                    c.clientName(),
                    c.principalEmail(),
                    c.scopes(),
                    c.lastActiveAt(),
                    c.refreshTokenExpiresAt());
        }
    }

    @GetMapping
    public List<McpConnectionResponse> list(
            @PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return connectionRepository.findByOrganization(orgId).stream()
                .map(McpConnectionResponse::from)
                .toList();
    }

    @DeleteMapping("/{registeredClientId}")
    public ResponseEntity<Void> revoke(
            @PathVariable UUID orgId,
            @PathVariable String registeredClientId,
            @RequestParam String principalEmail,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        int deleted = connectionRepository.revoke(orgId, registeredClientId, principalEmail);
        if (deleted == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        auditLogRepository.record(
                orgId,
                principal.userId(),
                principal.email(),
                "MCP_CONNECTION_REVOKED",
                "MCP_CLIENT",
                registeredClientId,
                "user=" + principalEmail);
        return ResponseEntity.noContent().build();
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
