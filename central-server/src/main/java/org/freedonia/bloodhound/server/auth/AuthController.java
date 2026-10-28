package org.freedonia.bloodhound.server.auth;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.auth.dto.ForgotPasswordRequest;
import org.freedonia.bloodhound.server.auth.dto.LoginRequest;
import org.freedonia.bloodhound.server.auth.dto.RefreshRequest;
import org.freedonia.bloodhound.server.auth.dto.ResetPasswordRequest;
import org.freedonia.bloodhound.server.notification.EmailSender;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.freedonia.bloodhound.server.security.WeakPasswordChecker;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * {@code @SecurityRequirements} (empty) overrides OpenApiConfig's global ApiKeyAuth requirement
 * for every operation here - a live API review found the generated spec claiming login/refresh/
 * logout needed a bearer token, which is backwards: these are how you GET a token, and
 * SecurityConfig permitAlls all of /api/v1/auth/**.
 */
@RestController
@RequestMapping("/api/v1/auth")
@SecurityRequirements
public class AuthController {

    private final AuthenticationService authenticationService;
    private final LoginAttemptLimiter loginAttemptLimiter;
    private final ForgotPasswordRateLimiter forgotPasswordRateLimiter;
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final WeakPasswordChecker weakPasswordChecker;
    private final AuditLogRepository auditLogRepository;
    private final EmailSender emailSender;
    private final String appBaseUrl;

    public AuthController(
            AuthenticationService authenticationService,
            LoginAttemptLimiter loginAttemptLimiter,
            ForgotPasswordRateLimiter forgotPasswordRateLimiter,
            UserRepository userRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepository,
            WeakPasswordChecker weakPasswordChecker,
            AuditLogRepository auditLogRepository,
            EmailSender emailSender,
            @Value("${bloodhound.notifications.app-base-url}") String appBaseUrl) {
        this.authenticationService = authenticationService;
        this.loginAttemptLimiter = loginAttemptLimiter;
        this.forgotPasswordRateLimiter = forgotPasswordRateLimiter;
        this.userRepository = userRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.weakPasswordChecker = weakPasswordChecker;
        this.auditLogRepository = auditLogRepository;
        this.emailSender = emailSender;
        this.appBaseUrl = appBaseUrl;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            return ResponseEntity.ok(AuthResponse.from(authenticationService.login(request.email(), request.password())));
        } catch (InvalidCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid email or password");
        } catch (LoginRateLimitedException e) {
            // A standard Retry-After header (RFC 9110 10.2.3), not just a status code - a product
            // review found the frontend had no reliable way to tell "you're rate-limited" apart
            // from any other failure without this, so it showed the same generic error message
            // for both. ResponseStatusException doesn't support adding response headers, hence
            // building the ResponseEntity directly here instead of throwing like the other cases.
            long retryAfterSeconds = loginAttemptLimiter.remainingLockoutSeconds(request.email());
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds))
                    .build();
        }
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshRequest request) {
        try {
            return AuthResponse.from(authenticationService.refresh(request.refreshToken()));
        } catch (InvalidRefreshTokenException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid or expired refresh token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest request) {
        authenticationService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    /**
     * Always responds the same way regardless of whether the email matches anything, how many
     * accounts it matches, or whether the email actually sends - an attacker must not be able to
     * tell "this email has an account" from "it doesn't" by probing this endpoint (the same
     * enumeration concern login's own generic "invalid email or password" message already
     * protects against, applied here too). {@code uq_users_org_email} is unique per
     * *organization*, not globally (see V1__init.sql), so the same email can legitimately match
     * more than one account - {@link UserRepository#findLocalActiveByEmail} already returns every
     * match, and this sends one token/email per match rather than picking one arbitrarily.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request, HttpServletRequest servletRequest) {
        String ip = servletRequest.getRemoteAddr();
        try {
            forgotPasswordRateLimiter.checkAllowed(ip, request.email());
        } catch (ForgotPasswordRateLimiter.ForgotPasswordRateLimitedException e) {
            long retryAfterSeconds = forgotPasswordRateLimiter.remainingLockoutSeconds(ip, request.email());
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds))
                    .build();
        }
        forgotPasswordRateLimiter.recordAttempt(ip, request.email());
        List<User> matches = userRepository.findLocalActiveByEmail(request.email());
        for (User user : matches) {
            String token = passwordResetTokenRepository.create(user.id());
            emailSender.send(
                    user.email(),
                    "Reset your Bloodhound password",
                    "Someone (hopefully you) requested a password reset for this Bloodhound account.\n\n"
                            + "Reset it here: " + appBaseUrl + "/reset-password?token=" + token + "\n\n"
                            + "This link expires in 1 hour. If you didn't request this, you can ignore this email -"
                            + " your password won't change unless you click the link above and set a new one.");
        }
        return ResponseEntity.accepted().build();
    }

    /**
     * A real response body, not a bare {@code ResponseStatusException} - this app's default error
     * handler never exposes a ResponseStatusException's reason text to the caller at all (the JSON
     * body is just {timestamp,status,error,path}, no message field - see
     * SlackIntegrationController.ErrorMessageResponse's own javadoc, which found and fixed this
     * exact gap elsewhere). Both failure cases below need the caller to actually see why, same as
     * UserSelfController#changePassword's own weak-password case does.
     */
    public record ErrorMessageResponse(String message) {}

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        Optional<UUID> userId = passwordResetTokenRepository.consume(request.token());
        if (userId.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorMessageResponse("This reset link is invalid or has expired - request a new one."));
        }
        User user = userRepository.findById(userId.get()).orElseThrow();
        if (weakPasswordChecker.isWeak(request.newPassword(), user.email())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorMessageResponse(
                            "This password is too common or easily guessed. Choose something less predictable."));
        }
        userRepository.updatePasswordHash(user.id(), passwordEncoder.encode(request.newPassword()));
        // Same "something changed, sign out everywhere" reasoning as UserSelfController#changePassword's
        // own revoke - doubly so here, since reaching this endpoint at all means someone (hopefully
        // the account owner) believed the password needed resetting in the first place.
        refreshTokenRepository.revokeAllForUser(user.id());
        // Self-service, like USER_PASSWORD_CHANGED - the "actor" is the account itself, reached
        // through an emailed link rather than an authenticated session, not an admin acting on it.
        auditLogRepository.record(
                user.organizationId(),
                user.id(),
                user.email(),
                "USER_PASSWORD_RESET_VIA_EMAIL",
                "USER",
                user.id().toString(),
                "email=" + user.email());
        return ResponseEntity.noContent().build();
    }
}
