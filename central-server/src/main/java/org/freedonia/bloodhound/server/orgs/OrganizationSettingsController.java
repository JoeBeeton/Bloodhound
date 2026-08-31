package org.freedonia.bloodhound.server.orgs;

import java.time.Instant;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.mcp.McpSigningKeyMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Org-wide settings not specific to any other admin area (SSO/SCIM/Slack/rules-catalog already
 * have their own controllers) - currently just the MCP server kill switch, see
 * Organization#mcpEnabled and mcp.McpEnabledGuardFilter for where it's actually enforced.
 */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/settings")
@PreAuthorize("hasRole('ADMIN')")
public class OrganizationSettingsController {

    private final OrganizationRepository organizationRepository;
    private final AuditLogRepository auditLogRepository;
    private final McpSigningKeyMetadata mcpSigningKeyMetadata;

    public OrganizationSettingsController(
            OrganizationRepository organizationRepository,
            AuditLogRepository auditLogRepository,
            McpSigningKeyMetadata mcpSigningKeyMetadata) {
        this.organizationRepository = organizationRepository;
        this.auditLogRepository = auditLogRepository;
        this.mcpSigningKeyMetadata = mcpSigningKeyMetadata;
    }

    /**
     * mcpSigningKeyGeneratedAt is JVM-wide (the same ephemeral keypair signs every org's MCP
     * tokens), not actually per-org data - included here anyway rather than adding a whole new
     * endpoint for one timestamp, since this is already the settings response every org admin
     * loading the MCP page fetches. See McpSigningKeyMetadata for why this equals the last
     * central-server restart, and AdminMcpPage.tsx for where it explains a client needing to
     * reconnect.
     */
    public record OrgSettingsResponse(boolean mcpEnabled, Instant mcpSigningKeyGeneratedAt) {
        static OrgSettingsResponse from(Organization org, Instant mcpSigningKeyGeneratedAt) {
            return new OrgSettingsResponse(org.mcpEnabled(), mcpSigningKeyGeneratedAt);
        }
    }

    public record UpdateOrgSettingsRequest(boolean mcpEnabled) {}

    @GetMapping
    public OrgSettingsResponse get(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return OrgSettingsResponse.from(requireOrg(orgId), mcpSigningKeyMetadata.generatedAt());
    }

    @PutMapping
    public OrgSettingsResponse update(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal JwtPrincipal principal,
            @RequestBody UpdateOrgSettingsRequest request) {
        requireSameOrg(orgId, principal);
        Organization before = requireOrg(orgId);
        organizationRepository.setMcpEnabled(orgId, request.mcpEnabled());
        // An audit review found this - the org-wide kill switch for AI-agent access to this
        // org's ASM data (see mcp.McpEnabledGuardFilter) - had no audit trail at all, unlike the
        // exact same shape of toggle on RulesCatalogController (RULE_ENABLED/RULE_DISABLED).
        // Only logged on an actual flip, not a redundant re-send of the current value.
        if (request.mcpEnabled() != before.mcpEnabled()) {
            auditLogRepository.record(
                    orgId,
                    principal.userId(),
                    principal.email(),
                    request.mcpEnabled() ? "MCP_ENABLED" : "MCP_DISABLED",
                    "ORGANIZATION",
                    orgId.toString(),
                    null);
        }
        return OrgSettingsResponse.from(requireOrg(orgId), mcpSigningKeyMetadata.generatedAt());
    }

    private Organization requireOrg(UUID orgId) {
        return organizationRepository.findById(orgId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
