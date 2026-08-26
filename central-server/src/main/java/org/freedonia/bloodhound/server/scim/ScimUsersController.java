package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
    private final String spBaseUrl;

    public ScimUsersController(
            ScimUserRepository scimUserRepository, @Value("${bloodhound.saml.sp-base-url}") String spBaseUrl) {
        this.scimUserRepository = scimUserRepository;
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
        try {
            ScimUserRow created = scimUserRepository.insert(
                    principal.organizationId(), request.userName(), displayName, request.activeOrDefault(), request.externalId());
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
        requireUser(principal, id);
        requireUserName(request.userName());
        String displayName = ScimUserResource.combineDisplayName(request.name(), request.displayName());
        try {
            scimUserRepository.replace(
                    principal.organizationId(), id, request.userName(), displayName, request.activeOrDefault(), request.externalId());
        } catch (DataIntegrityViolationException e) {
            throw scimError(HttpStatus.CONFLICT, "A user with this userName already exists in this organization");
        }
        return ScimUserResource.from(requireUser(principal, id), spBaseUrl);
    }

    @PatchMapping("/{id}")
    public ScimUserResource patch(
            @AuthenticationPrincipal ScimPrincipal principal, @PathVariable UUID id, @RequestBody ScimPatchRequest request) {
        ScimUserRow current = requireUser(principal, id);
        ScimPatchPlan plan = ScimPatchProcessor.apply(request.operations(), current.displayName());
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
        requireUser(principal, id);
        scimUserRepository.updateActive(principal.organizationId(), id, false);
        return ResponseEntity.noContent().build();
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
    }

    private ResponseStatusException scimError(HttpStatus status, String detail) {
        // Turned into the real RFC 7644 3.12 SCIM error JSON body by ScimExceptionHandler,
        // scoped to just this package - the app has no other global exception handling
        // (confirmed: default Spring Boot error shape everywhere else is fine for the JSON
        // API, but not SCIM-conformant), so this only changes behavior under /scim/v2/**.
        return new ResponseStatusException(status, detail);
    }
}
