package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.server.apikey.ApiKeyRepository;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.scim.dto.ScimListResponse;
import org.freedonia.bloodhound.server.scim.dto.ScimPatchRequest;
import org.freedonia.bloodhound.server.scim.dto.ScimUserResource;
import org.freedonia.bloodhound.server.scim.dto.ScimUserWriteRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * RFC 7644 Users resource - the SCIM endpoints an IdP actually pushes
 * provisioning events to. Every operation is scoped to the calling
 * ScimPrincipal's organizationId (set by ScimTokenAuthFilter from the
 * bearer token's own org, not from any client-supplied value), so a token
 * for org A can't read/write org B's users no matter what id is requested.
 */
@RestController
@RequestMapping(value = "/scim/v2/Users", produces = "application/scim+json")
@PreAuthorize("hasRole('SCIM')")
public class ScimUsersController {

    // Deliberately supports exactly the one filter shape real SCIM clients (Okta, Azure AD) send in
    // practice - a userName-existence check before creating - not a general SCIM filter grammar.
    // Case-insensitive on `eq`, tolerant of extra whitespace, double- or single-quoted value.
    private static final Pattern USERNAME_EQ_FILTER =
            Pattern.compile("userName\\s+eq\\s+[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    private final ScimUserRepository scimUserRepository;
    private final AuditLogRepository auditLogRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApiKeyRepository apiKeyRepository;
    private final String spBaseUrl;

    public ScimUsersController(
            ScimUserRepository scimUserRepository,
            AuditLogRepository auditLogRepository,
            RefreshTokenRepository refreshTokenRepository,
            ApiKeyRepository apiKeyRepository,
            @Value("${bloodhound.saml.sp-base-url}") String spBaseUrl) {
        this.scimUserRepository = scimUserRepository;
        this.auditLogRepository = auditLogRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.apiKeyRepository = apiKeyRepository;
        this.spBaseUrl = spBaseUrl;
    }

    @GetMapping
    public ScimListResponse list(
            @AuthenticationPrincipal ScimPrincipal principal,
            @RequestParam(required = false) String filter,
            @RequestParam(defaultValue = "1") int startIndex,
            @RequestParam(defaultValue = "100") int count) {
        Matcher matcher = filter == null ? null : USERNAME_EQ_FILTER.matcher(filter);
        if (matcher != null && matcher.find()) {
            Optional<ScimUserRow> match = scimUserRepository.findByOrgAndUserName(principal.organizationId(), matcher.group(1));
            List<ScimUserResource> resources =
                    match.map(row -> List.of(ScimUserResource.from(row, spBaseUrl))).orElse(List.of());
            return ScimListResponse.of(resources, resources.size(), 1, resources.size());
        }
        long total = scimUserRepository.countByOrg(principal.organizationId());
        List<ScimUserResource> resources = scimUserRepository.listByOrg(principal.organizationId(), startIndex, count).stream()
                .map(row -> ScimUserResource.from(row, spBaseUrl))
                .toList();
        return ScimListResponse.of(resources, (int) total, startIndex, resources.size());
    }

    @PostMapping
    public ResponseEntity<ScimUserResource> create(
            @AuthenticationPrincipal ScimPrincipal principal, @RequestBody ScimUserWriteRequest request) {
        requireUserName(request.userName());
        String displayName = ScimUserResource.combineDisplayName(request.name(), request.displayName());
        requireWithinLength(displayName, "displayName", MAX_DISPLAY_NAME_LENGTH);
        requireWithinLength(request.externalId(), "externalId", MAX_EXTERNAL_ID_LENGTH);
        try {
            ScimUserRow created = scimUserRepository.insert(
                    principal.organizationId(), request.userName(), displayName, request.activeOrDefault(), request.externalId());
            // An audit review found this whole controller - the actual execution path an external
            // IdP uses to provision/deprovision accounts in this org - had no audit trail at all,
            // a real blind spot: a misconfigured IdP mapping or a compromised SCIM token could
            // silently create or disable accounts with nothing to show for it in the shared Audit
            // Log page. actorUserId is null (there's no human behind a SCIM call, see
            // ScimPrincipal's own fields) - actorEmail carries the token's own label instead, so
            // an admin reading the log can still tell *which* SCIM integration did this.
            recordScimAudit(principal, "SCIM_USER_CREATED", created.id(), "userName=" + created.userName());
            return ResponseEntity.status(HttpStatus.CREATED).body(ScimUserResource.from(created, spBaseUrl));
        } catch (DataIntegrityViolationException e) {
            throw scimError(HttpStatus.CONFLICT, "A user with this userName already exists in this organization");
        }
    }

    @GetMapping("/{id}")
    public ScimUserResource get(@AuthenticationPrincipal ScimPrincipal principal, @PathVariable UUID id) {
        return ScimUserResource.from(requireUser(principal, id), spBaseUrl);
    }

    @PutMapping("/{id}")
    public ScimUserResource replace(
            @AuthenticationPrincipal ScimPrincipal principal, @PathVariable UUID id, @RequestBody ScimUserWriteRequest request) {
        ScimUserRow before = requireUser(principal, id);
        requireUserName(request.userName());
        String displayName = ScimUserResource.combineDisplayName(request.name(), request.displayName());
        requireWithinLength(displayName, "displayName", MAX_DISPLAY_NAME_LENGTH);
        requireWithinLength(request.externalId(), "externalId", MAX_EXTERNAL_ID_LENGTH);
        try {
            scimUserRepository.replace(
                    principal.organizationId(), id, request.userName(), displayName, request.activeOrDefault(), request.externalId());
        } catch (DataIntegrityViolationException e) {
            throw scimError(HttpStatus.CONFLICT, "A user with this userName already exists in this organization");
        }
        // Only the active flip is audit-worthy here, same restraint the isActive/mcpEnabled fixes
        // elsewhere in this app already apply - a userName/displayName sync via SCIM is routine
        // profile upkeep, not a security-relevant state transition.
        recordScimActiveStatusChange(principal, id, before.active(), request.activeOrDefault());
        return ScimUserResource.from(requireUser(principal, id), spBaseUrl);
    }

    @PatchMapping("/{id}")
    public ScimUserResource patch(
            @AuthenticationPrincipal ScimPrincipal principal, @PathVariable UUID id, @RequestBody ScimPatchRequest request) {
        ScimUserRow current = requireUser(principal, id);
        ScimPatchPlan plan = ScimPatchProcessor.apply(request.operations(), current.displayName());
        requireWithinLength(plan.userName(), "userName", MAX_USERNAME_LENGTH);
        requireWithinLength(plan.displayName(), "displayName", MAX_DISPLAY_NAME_LENGTH);
        try {
            if (plan.active() != null) {
                scimUserRepository.updateActive(principal.organizationId(), id, plan.active());
            }
            if (plan.userName() != null) {
                scimUserRepository.updateUserName(principal.organizationId(), id, plan.userName());
            }
            if (plan.displayName() != null) {
                scimUserRepository.updateDisplayName(principal.organizationId(), id, plan.displayName());
            }
        } catch (DataIntegrityViolationException e) {
            throw scimError(HttpStatus.CONFLICT, "A user with this userName already exists in this organization");
        }
        if (plan.active() != null) {
            recordScimActiveStatusChange(principal, id, current.active(), plan.active());
        }
        return ScimUserResource.from(requireUser(principal, id), spBaseUrl);
    }

    /**
     * RFC 7644 describes DELETE as resource removal, but this project already established
     * disable-not-delete as the correct "remove a user" semantic elsewhere (the admin-UI user
     * removal feature) specifically because hard-deleting a user orphans triggered_by_user_id
     * references on scan_runs/target_authorizations - SCIM DELETE follows that same precedent
     * rather than introducing a second, more destructive removal path.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deactivate(@AuthenticationPrincipal ScimPrincipal principal, @PathVariable UUID id) {
        ScimUserRow before = requireUser(principal, id);
        scimUserRepository.updateActive(principal.organizationId(), id, false);
        recordScimActiveStatusChange(principal, id, before.active(), false);
        return ResponseEntity.noContent().build();
    }

    /**
     * Only acts on a real transition - a redundant PATCH/PUT/DELETE re-sending the account's
     * current active value does nothing.
     *
     * <p>A security review found deactivation here only ever flipped {@code users.status} -
     * unlike the admin-UI path ({@code OrgUserController}), which also revokes refresh tokens and
     * API keys on exactly this transition. A refresh token stays valid until its next use (the
     * ACTIVE check only runs at refresh time) and an API key has no live check at all, so an
     * offboarded SCIM user kept read access for as long as their existing tokens/keys happened to
     * still be valid - the identical gap already fixed for the admin UI, just not here too.
     */
    private void recordScimActiveStatusChange(ScimPrincipal principal, UUID userId, boolean before, boolean after) {
        if (before == after) {
            return;
        }
        if (!after) {
            refreshTokenRepository.revokeAllForUser(userId);
            apiKeyRepository.revokeAllForUser(userId);
        }
        recordScimAudit(principal, after ? "SCIM_USER_ACTIVATED" : "SCIM_USER_DEACTIVATED", userId, null);
    }

    private void recordScimAudit(ScimPrincipal principal, String action, UUID targetUserId, String detail) {
        auditLogRepository.record(
                principal.organizationId(),
                null,
                "SCIM: " + principal.tokenLabel(),
                action,
                "USER",
                targetUserId.toString(),
                detail);
    }

    private ScimUserRow requireUser(ScimPrincipal principal, UUID id) {
        return scimUserRepository
                .findByOrgAndId(principal.organizationId(), id)
                .orElseThrow(() -> scimError(HttpStatus.NOT_FOUND, "User " + id + " not found"));
    }

    private void requireUserName(String userName) {
        if (userName == null || userName.isBlank()) {
            throw scimError(HttpStatus.BAD_REQUEST, "userName is required");
        }
        requireWithinLength(userName, "userName", MAX_USERNAME_LENGTH);
    }

    /**
     * A security review found none of userName/displayName/externalId had any length cap at all,
     * anywhere in this controller or its request DTOs - the same "attacker/misconfiguration-
     * influenced free text stored unbounded" gap already fixed for target notes (@Size(max=2000))
     * and the MCP OAuth2 client_name field this session. userName/displayName write straight into
     * the shared `users` table's email/display_name columns (both plain TEXT, no DB-level limit
     * either) - the exact same columns local-login users and SAML SSO share, so an oversized value
     * here doesn't just bloat this one row, it flows into every other page that renders a user's
     * email/display name (Users admin page, Audit Log, dropdowns) the same way any other user's
     * would. Reachable by anything holding a valid SCIM bearer token - already-authenticated, but
     * a compromised token or a misconfigured IdP integration pushing malformed provisioning
     * payloads is a realistic way to hit this, not a purely theoretical one.
     */
    private static final int MAX_USERNAME_LENGTH = 320; // RFC 5321's own max total email length.

    private static final int MAX_DISPLAY_NAME_LENGTH = 200; // Matches the cap MCP client_name uses.
    private static final int MAX_EXTERNAL_ID_LENGTH = 200; // An opaque IdP-assigned id - never legitimately long.

    private void requireWithinLength(String value, String fieldName, int max) {
        if (value != null && value.length() > max) {
            throw scimError(HttpStatus.BAD_REQUEST, fieldName + " must be " + max + " characters or fewer");
        }
    }

    private ResponseStatusException scimError(HttpStatus status, String detail) {
        // Turned into the real RFC 7644 3.12 SCIM error JSON body by ScimExceptionHandler,
        // scoped to just this package - the app has no other global exception handling
        // (confirmed: default Spring Boot error shape everywhere else is fine for the JSON
        // API, but not SCIM-conformant), so this only changes behavior under /scim/v2/**.
        return new ResponseStatusException(status, detail);
    }
}
