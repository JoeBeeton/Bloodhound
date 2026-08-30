package org.freedonia.bloodhound.server.orgs;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.orgs.dto.CreateUserRequest;
import org.freedonia.bloodhound.server.orgs.dto.CreateUserResponse;
import org.freedonia.bloodhound.server.orgs.dto.UpdateUserRequest;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Minimal user administration, scoped to the admin's own organization. Full
 * CRUD polish isn't the point yet - this exists mainly to prove the RBAC and
 * org-scoping model works end to end.
 */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/users")
@PreAuthorize("hasRole('ADMIN')")
public class OrgUserController {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditLogRepository auditLogRepository;

    public OrgUserController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepository,
            AuditLogRepository auditLogRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping
    public List<UserSummary> list(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return userRepository.findByOrganizationId(orgId).stream()
                .map(UserSummary::from)
                .toList();
    }

    /**
     * Creates a local user with a randomly-generated temporary password,
     * returned once in the response body (see CreateUserResponse) - there's
     * no email-sending infrastructure in this project, so the admin is
     * responsible for relaying it out-of-band. The new user should change it
     * via PATCH /api/v1/users/me/password on first login.
     */
    @PostMapping
    public ResponseEntity<CreateUserResponse> create(
            @PathVariable UUID orgId,
            @Valid @RequestBody CreateUserRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        String temporaryPassword = generateTemporaryPassword();
        try {
            User created = userRepository.insertLocalUser(
                    orgId, request.email(), request.displayName(), request.role(), passwordEncoder.encode(temporaryPassword));
            auditLogRepository.record(
                    orgId,
                    principal.userId(),
                    principal.email(),
                    "USER_CREATED",
                    "USER",
                    created.id().toString(),
                    "email=" + created.email() + " role=" + created.role());
            return ResponseEntity.status(HttpStatus.CREATED).body(CreateUserResponse.of(created, temporaryPassword));
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "a user with that email already exists in this organization");
        }
    }

    /**
     * The only recourse for a LOCAL user who forgot their password - there's no self-serve
     * "forgot password" flow, since (as with user creation, see #create) there's no
     * email-sending infrastructure in this project to deliver a reset link to. Rejects SAML
     * users: they have no password_hash to reset (auth happens entirely at the IdP), so this
     * would silently do nothing useful for them. Revokes every existing session for the user,
     * the same as a self-service password change already does (see
     * UserSelfController#changePassword) - if the account was reset because it was compromised,
     * this is also what cuts off whoever was already logged in as them.
     */
    @PostMapping("/{id}/reset-password")
    public CreateUserResponse resetPassword(
            @PathVariable UUID orgId, @PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        User target = userRepository
                .findById(id)
                .filter(u -> u.organizationId().equals(orgId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (!"LOCAL".equals(target.identitySource())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "this user signs in via SSO and has no local password to reset");
        }
        String temporaryPassword = generateTemporaryPassword();
        userRepository.updatePasswordHash(id, passwordEncoder.encode(temporaryPassword));
        refreshTokenRepository.revokeAllForUser(id);
        auditLogRepository.record(
                orgId,
                principal.userId(),
                principal.email(),
                "USER_PASSWORD_RESET",
                "USER",
                id.toString(),
                "email=" + target.email());
        return CreateUserResponse.of(userRepository.findById(id).orElseThrow(), temporaryPassword);
    }

    @PatchMapping("/{id}")
    public UserSummary update(
            @PathVariable UUID orgId,
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        User target = userRepository
                .findById(id)
                .filter(u -> u.organizationId().equals(orgId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        // Enforced here, not just as a disabled control in the UI: a direct API
        // call must not be able to lock an admin out of their own account
        // (role or status) by acting on themselves.
        if (id.equals(principal.userId()) && (request.role() != null || request.status() != null)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "cannot change your own role or status");
        }

        String newRole = request.role() != null ? request.role() : target.role();
        String newStatus = request.status() != null ? request.status() : target.status();
        boolean updated = userRepository.updateRoleAndStatus(id, newRole, newStatus);
        if (!updated) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "cannot demote or deactivate the organization's last remaining admin");
        }
        if (!newRole.equals(target.role()) || !newStatus.equals(target.status())) {
            auditLogRepository.record(
                    orgId,
                    principal.userId(),
                    principal.email(),
                    "USER_ROLE_OR_STATUS_CHANGED",
                    "USER",
                    id.toString(),
                    "email=" + target.email() + " role=" + target.role() + "->" + newRole + " status=" + target.status()
                            + "->" + newStatus);
        }
        // No last-admin-style invariant and no lockout risk here (unlike role/status above) - an
        // admin toggling their own MCP access, or another user's, is an ordinary permission change,
        // so self-modification is allowed.
        if (request.mcpEnabled() != null) {
            userRepository.setMcpEnabled(id, request.mcpEnabled());
        }
        return UserSummary.from(userRepository.findById(id).orElseThrow());
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!principal.organizationId().equals(orgId)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "cannot manage users outside your organization");
        }
    }

    private static String generateTemporaryPassword() {
        byte[] randomBytes = new byte[18];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
