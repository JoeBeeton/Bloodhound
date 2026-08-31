package org.freedonia.bloodhound.server.orgs;

import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.freedonia.bloodhound.server.auth.LoginRateLimitedException;
import org.freedonia.bloodhound.server.auth.RefreshToken;
import org.freedonia.bloodhound.server.auth.RefreshTokenRepository;
import org.freedonia.bloodhound.server.orgs.dto.ChangePasswordRequest;
import org.freedonia.bloodhound.server.orgs.dto.LogoutOtherSessionsRequest;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.freedonia.bloodhound.server.security.WeakPasswordChecker;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Self-service actions for the currently-authenticated user - closes the loop
 * for an admin-created user (or the bootstrap admin, stuck with whatever
 * .env placeholder was configured) to actually rotate off a temporary or
 * placeholder password. Only ever acts on the caller's own account.
 */
@RestController
@RequestMapping("/api/v1/users/me")
public class UserSelfController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginAttemptLimiter loginAttemptLimiter;
    private final AuditLogRepository auditLogRepository;
    private final WeakPasswordChecker weakPasswordChecker;

    public UserSelfController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepository,
            LoginAttemptLimiter loginAttemptLimiter,
            AuditLogRepository auditLogRepository,
            WeakPasswordChecker weakPasswordChecker) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.loginAttemptLimiter = loginAttemptLimiter;
        this.auditLogRepository = auditLogRepository;
        this.weakPasswordChecker = weakPasswordChecker;
    }

    /**
     * A security review found this was the one other place in the app that verifies a password
     * against its stored hash (see AuthenticationService#login for the other) with no brute-force
     * guard at all - an attacker holding a stolen but still-valid session (an XSS'd access token,
     * a leaked refresh cookie) could try unlimited currentPassword guesses here, bounded only by
     * BCrypt's own cost, to recover the account's real password - useful to them well beyond that
     * one session's lifetime, and for credential-stuffing anywhere the user reuses it. Reuses
     * LoginAttemptLimiter as-is (same 10-attempts/15-minute window, keyed by email) rather than a
     * second limiter instance - it's the exact same "someone is guessing a password" threat this
     * endpoint just happens to reach through a JWT instead of a login form, and sharing it means
     * the two paths' failures count against one combined lockout per email rather than each
     * getting its own independent budget of guesses.
     */
    /** The weak-password rejection's own response body - see the comment on that branch below for why this one case needs one. */
    public record WeakPasswordResponse(String message) {}

    @PatchMapping("/password")
    public ResponseEntity<?> changePassword(
            @Valid @RequestBody ChangePasswordRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        try {
            loginAttemptLimiter.checkAllowed(principal.email());
        } catch (LoginRateLimitedException e) {
            long retryAfterSeconds = loginAttemptLimiter.remainingLockoutSeconds(principal.email());
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds))
                    .build();
        }
        User user = userRepository.findById(principal.userId()).orElseThrow();
        if (!"LOCAL".equals(user.identitySource()) || user.passwordHash() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "this account doesn't use a local password");
        }
        if (!passwordEncoder.matches(request.currentPassword(), user.passwordHash())) {
            loginAttemptLimiter.recordFailure(principal.email());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "current password is incorrect");
        }
        loginAttemptLimiter.recordSuccess(principal.email());
        // A security review found this only validated newPassword's length (see
        // ChangePasswordRequest's own @Size) - nothing stopped it from being a trivially
        // guessable value like "password1" or the account's own email. NIST 800-63B's current
        // guidance (SP 800-63B §5.1.1.2) is explicit that composition rules (require a digit, a
        // symbol, etc.) are NOT recommended, but SHALL compare against known-common/compromised
        // values and against context-specific ones (the account's own username) - this is exactly
        // that check, not a composition-rule requirement. Checked only after the current-password
        // verification above, not before: a caller who doesn't already know the real current
        // password shouldn't learn anything about what would or wouldn't be accepted as a new one.
        //
        // Returns a real response body, unlike the two ResponseStatusException checks above -
        // confirmed live that this app's default error handler (unlike SCIM's own
        // package-scoped ScimExceptionHandler) never exposes a ResponseStatusException's reason
        // text to the caller at all (the JSON body is just {timestamp,status,error,path}, no
        // message field), the same reason ChangePasswordModal.tsx's own frontend code has to
        // hardcode "Current password is incorrect." for a 403 rather than reading it from the
        // body. A generic "your password was rejected" would be actively unhelpful here - the
        // whole point of this check is telling the user specifically why, so they can pick
        // something that will actually be accepted.
        if (weakPasswordChecker.isWeak(request.newPassword(), principal.email())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new WeakPasswordResponse(
                            "This password is too common or easily guessed. Choose something less predictable."));
        }
        userRepository.updatePasswordHash(user.id(), passwordEncoder.encode(request.newPassword()));
        // A security review found this self-service change had no audit trail, unlike the
        // admin-triggered equivalent (OrgUserController's own USER_PASSWORD_RESET) - a distinct
        // action name, not the same one, so an admin reviewing the log can tell "the user changed
        // it themselves" apart from "an admin reset it for them". Password changes are exactly
        // the kind of event compliance frameworks expect logged - both as routine self-service
        // hygiene and because "change the password" is also a common step in an actual account
        // takeover, which this entry helps an incident review reconstruct.
        auditLogRepository.record(
                principal.organizationId(), user.id(), principal.email(), "USER_PASSWORD_CHANGED", "USER", user.id().toString(),
                "email=" + principal.email());
        // A security review found that changing your password previously left every other
        // active session (refresh token / httpOnly cookie, on any device, including the caller's
        // own current one) completely valid - revoking them all here is the actual point of "I
        // think my account is compromised, change my password" as a self-remediation action.
        // This does sign the caller themselves out too (their next /refresh will fail and they'll
        // need to log in again) - the same "signed out everywhere" behavior a password change
        // triggers on most major platforms, not an oversight.
        refreshTokenRepository.revokeAllForUser(user.id());
        return ResponseEntity.noContent().build();
    }

    public record ActiveSessionsCount(int count) {}

    /**
     * "You have N active sessions" (including the one asking) - shown before offering the
     * logout-others action below, so it's an informed decision rather than a mystery button.
     * Deliberately a plain GET with no token in the query string - see
     * RefreshTokenRepository#countActiveForUser's javadoc for why this doesn't need one.
     */
    @GetMapping("/sessions/count")
    public ActiveSessionsCount countActiveSessions(@AuthenticationPrincipal JwtPrincipal principal) {
        return new ActiveSessionsCount(refreshTokenRepository.countActiveForUser(principal.userId()));
    }

    /**
     * "Log out of all other devices" - a user-initiated version of the same session hygiene the
     * password-change flow above forces automatically. Useful on its own (a shared/public
     * computer, a lost device, "something feels off") without also having to change your password
     * to get it - the caller's own current session (identified by its raw refresh token) is left
     * untouched so this request's own caller isn't locked out by their own action.
     */
    @PostMapping("/sessions/logout-others")
    public ResponseEntity<Void> logoutOtherSessions(
            @Valid @RequestBody LogoutOtherSessionsRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        refreshTokenRepository.revokeAllForUserExceptHash(
                principal.userId(), HashUtil.sha256Hex(request.currentRefreshToken()));
        // Same reasoning as changePassword's own new audit entry above - "something feels off, log
        // out everywhere else" is exactly the kind of self-remediation an incident review benefits
        // from being able to see happened (and when), not just infer from a sudden drop in active
        // session count.
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "USER_LOGGED_OUT_OTHER_SESSIONS",
                "USER",
                principal.userId().toString(),
                "email=" + principal.email());
        return ResponseEntity.noContent().build();
    }

    /**
     * sessionStartedAt/expiresAt only - no device name, browser, or IP, because refresh_tokens
     * doesn't capture any of that today (see RefreshTokenRepository#listActiveForUser's own
     * comment). Still real value over the count-only endpoint above: a user can now see roughly
     * *how many* sessions there are and *when* each began, enough to recognize "I only ever use
     * this from two places, why are there four rows" even without a friendly device label -
     * capturing User-Agent/IP at issuance to make this fully self-explanatory is a natural
     * follow-up, deliberately left out of this pass to keep it to central-server alone (that would
     * mean threading request context through AuthenticationService#issueTokens, used by both the
     * local-login and SAML-success paths).
     */
    public record SessionSummary(UUID id, Instant sessionStartedAt, Instant createdAt, Instant expiresAt) {
        static SessionSummary from(RefreshToken t) {
            return new SessionSummary(t.id(), t.sessionStartedAt(), t.createdAt(), t.expiresAt());
        }
    }

    @GetMapping("/sessions")
    public List<SessionSummary> listSessions(@AuthenticationPrincipal JwtPrincipal principal) {
        return refreshTokenRepository.listActiveForUser(principal.userId()).stream()
                .map(SessionSummary::from)
                .toList();
    }

    /**
     * Ends one specific session by id, unlike logout-others above which is all-or-nothing - lets a
     * user recognize a single stale/unrecognized entry in the list above (by when it started) and
     * end just that one without also signing themselves out of every other device. No special
     * case for "is this my own current session" - there's no reliable way to tell from here which
     * row that is (see SessionSummary's own comment), and revoking your own current session is a
     * harmless, unsurprising action anyway: it's exactly what a normal logout already does.
     */
    @DeleteMapping("/sessions/{id}")
    public ResponseEntity<Void> revokeSession(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        int updated = refreshTokenRepository.revokeOwnedByUser(id, principal.userId());
        if (updated == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "USER_SESSION_REVOKED",
                "USER",
                principal.userId().toString(),
                "sessionId=" + id);
        return ResponseEntity.noContent().build();
    }
}
