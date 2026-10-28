package org.freedonia.bloodhound.server.orgs;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import org.freedonia.bloodhound.server.apikey.ApiKeyRepository;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.PasswordResetTokenRepository;
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.notification.EmailSender;
import org.freedonia.bloodhound.server.orgs.dto.CreateUserRequest;
import org.freedonia.bloodhound.server.orgs.dto.CreateUserResponse;
import org.freedonia.bloodhound.server.orgs.dto.InviteSentResponse;
import org.freedonia.bloodhound.server.orgs.dto.UpdateUserRequest;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.springframework.beans.factory.annotation.Value;
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
    /** How long an invite's "set your password" link stays valid - much longer than forgot-password's own default 1-hour TTL (PasswordResetTokenRepository), since nobody's actively waiting on this one right after requesting it. */
    private static final Duration INVITE_LINK_TTL = Duration.ofDays(7);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApiKeyRepository apiKeyRepository;
    private final AuditLogRepository auditLogRepository;
    private final EmailSender emailSender;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final String appBaseUrl;

    public OrgUserController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepository,
            ApiKeyRepository apiKeyRepository,
            AuditLogRepository auditLogRepository,
            EmailSender emailSender,
            PasswordResetTokenRepository passwordResetTokenRepository,
            @Value("${bloodhound.notifications.app-base-url}") String appBaseUrl) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.apiKeyRepository = apiKeyRepository;
        this.auditLogRepository = auditLogRepository;
        this.emailSender = emailSender;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.appBaseUrl = appBaseUrl;
    }

    @GetMapping
    public List<UserSummary> list(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return userRepository.findByOrganizationId(orgId).stream()
                .map(UserSummary::from)
                .toList();
    }

    /**
     * Creates a local user with no password the admin ever sees - unlike #resetPassword below,
     * there's no temporary password to relay out-of-band here at all, deliberately: a product/
     * security review found handing an admin a password to copy and send to someone else (even
     * "securely") is a weaker pattern than the new user picking their own, the moment real
     * email-sending infra existed to make that practical (see EmailSender). The row still needs
     * *some* password_hash (LOCAL identity_source expects a real one - see V1__init.sql's own
     * comment), so one is generated and encoded exactly as before, just never returned or emailed
     * anywhere - it's unknown and unguessable, a pure placeholder until the invite link below is
     * used. That link reuses the identical password_reset_tokens mechanism and
     * POST /api/v1/auth/reset-password endpoint self-serve "forgot password" already uses
     * (AuthController) - "set a new password for this user_id" is the same operation either way,
     * just with a much longer TTL here (INVITE_LINK_TTL) since nobody's actively waiting on it the
     * way a forgot-password requester is.
     */
    @PostMapping
    public ResponseEntity<InviteSentResponse> create(
            @PathVariable UUID orgId,
            @Valid @RequestBody CreateUserRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        String unusablePlaceholderPassword = generateTemporaryPassword();
        try {
            User created = userRepository.insertLocalUser(
                    orgId,
                    request.email(),
                    request.displayName(),
                    request.role(),
                    passwordEncoder.encode(unusablePlaceholderPassword));
            auditLogRepository.record(
                    orgId,
                    principal.userId(),
                    principal.email(),
                    "USER_CREATED",
                    "USER",
                    created.id().toString(),
                    "email=" + created.email() + " role=" + created.role());
            String token = passwordResetTokenRepository.create(created.id(), INVITE_LINK_TTL);
            // Best-effort - see EmailSender's own javadoc for why a slow/failed send never blocks
            // or fails this request. Unlike #resetPassword below, there is no fallback if this
            // doesn't arrive - an admin who needs to recover from that re-runs this endpoint (or a
            // future resend action) rather than falling back to a password they'd have to relay.
            emailSender.send(
                    created.email(),
                    "You've been added to Bloodhound",
                    "An account was created for you in Bloodhound.\n\n"
                            + "Set your password here: " + appBaseUrl + "/reset-password?token=" + token + "\n\n"
                            + "This link expires in 7 days.");
            return ResponseEntity.status(HttpStatus.CREATED).body(InviteSentResponse.of(created));
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "a user with that email already exists in this organization");
        }
    }

    /**
     * The admin-initiated recourse for a LOCAL user who forgot their password - distinct from the
     * self-serve AuthController#forgotPassword, which the account holder can use themselves
     * without an admin at all. Unlike #create above, this one deliberately still hands back a
     * real, usable temporary password (see CreateUserResponse) rather than an invite-style link:
     * an admin resetting someone else's password is already acting on their behalf (often because
     * that person can't get in and asked for help), so there's no "let them set their own" step
     * to defer to the way a brand-new invite has. Rejects SAML users: they have no password_hash
     * to reset (auth happens entirely at the IdP), so this would silently do nothing useful for
     * them. Revokes every existing session for the user, the same as a self-service password
     * change already does (see UserSelfController#changePassword) - if the account was reset
     * because it was compromised, this is also what cuts off whoever was already logged in as
     * them.
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
        // Best-effort, same reasoning as #create's own send above - the temporary password
        // returned below is still the fallback if this doesn't arrive.
        emailSender.send(
                target.email(),
                "Your Bloodhound password was reset",
                "An administrator reset your Bloodhound password.\n\n"
                        + "Temporary password: " + temporaryPassword + "\n\n"
                        + "Sign in at " + appBaseUrl + "/login - you'll be asked to change this password.\n\n"
                        + "If you didn't expect this, contact your organization's admin.");
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
        // A security review found disabling a user here revoked nothing at all: refresh tokens
        // stayed valid until their next use (the ACTIVE check only runs at refresh time, see
        // AuthenticationService#refresh) and API keys - which have no such live check anywhere,
        // see ApiKey#isActive - kept working for up to their full remaining expiry (default 90
        // days). An offboarded, or compromised-then-disabled, user kept read access to this org's
        // targets/findings/scans for as long as their existing tokens/keys happened to still be
        // valid. Only fires on an actual transition INTO DISABLED, not every redundant re-send of
        // the same status, matching this controller's own audit-logging condition just below.
        if ("DISABLED".equals(newStatus) && !newStatus.equals(target.status())) {
            refreshTokenRepository.revokeAllForUser(id);
            apiKeyRepository.revokeAllForUser(id);
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
