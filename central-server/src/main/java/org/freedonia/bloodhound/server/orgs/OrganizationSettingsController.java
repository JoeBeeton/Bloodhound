package org.freedonia.bloodhound.server.orgs;

import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
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

    public OrganizationSettingsController(
            OrganizationRepository organizationRepository, AuditLogRepository auditLogRepository) {
        this.organizationRepository = organizationRepository;
        this.auditLogRepository = auditLogRepository;
    }

    public record OrgSettingsResponse(boolean mcpEnabled) {
        static OrgSettingsResponse from(Organization org) {
            return new OrgSettingsResponse(org.mcpEnabled());
        }
    }

    public record UpdateOrgSettingsRequest(boolean mcpEnabled) {}

    @GetMapping
    public OrgSettingsResponse get(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return OrgSettingsResponse.from(requireOrg(orgId));
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
        return OrgSettingsResponse.from(requireOrg(orgId));
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
