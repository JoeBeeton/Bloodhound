package org.freedonia.bloodhound.server.audit;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** ADMIN-only, same org-scoping convention as OrgUserController - this is exactly the kind of record an org's own admins should be able to review, and no one else. */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/audit-log")
@PreAuthorize("hasRole('ADMIN')")
public class AuditLogController {

    private static final int DEFAULT_LIMIT = 50;
    private static final int MAX_LIMIT = 200;

    private final AuditLogRepository auditLogRepository;

    public AuditLogController(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping
    public ResponseEntity<List<AuditLogEntry>> list(
            @PathVariable UUID orgId,
            @RequestParam(required = false) String actorEmail,
            @RequestParam(required = false) String action,
            @RequestParam(defaultValue = "" + DEFAULT_LIMIT) int limit,
            @RequestParam(defaultValue = "0") int offset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        if (!principal.organizationId().equals(orgId)) {
            throw new ResponseStatusException(
                    org.springframework.http.HttpStatus.FORBIDDEN, "cannot view audit history outside your organization");
        }
        int boundedLimit = Math.clamp(limit, 1, MAX_LIMIT);
        int boundedOffset = Math.max(offset, 0);
        List<AuditLogEntry> page =
                auditLogRepository.findByOrganization(orgId, actorEmail, action, boundedLimit, boundedOffset);
        int totalCount = auditLogRepository.countByOrganization(orgId, actorEmail, action);
        return ResponseEntity.ok().header("X-Total-Count", String.valueOf(totalCount)).body(page);
    }
}
