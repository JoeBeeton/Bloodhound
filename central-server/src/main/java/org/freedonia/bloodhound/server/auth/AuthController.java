package org.freedonia.bloodhound.server.auth;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.validation.Valid;
import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.auth.dto.LoginRequest;
import org.freedonia.bloodhound.server.auth.dto.RefreshRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    public AuthController(AuthenticationService authenticationService, LoginAttemptLimiter loginAttemptLimiter) {
        this.authenticationService = authenticationService;
        this.loginAttemptLimiter = loginAttemptLimiter;
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
}
