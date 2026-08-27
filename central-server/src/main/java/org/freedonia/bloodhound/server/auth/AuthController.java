package org.freedonia.bloodhound.server.auth;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.validation.Valid;
import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.auth.dto.LoginRequest;
import org.freedonia.bloodhound.server.auth.dto.RefreshRequest;
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

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        try {
            return AuthResponse.from(authenticationService.login(request.email(), request.password()));
        } catch (InvalidCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid email or password");
        } catch (LoginRateLimitedException e) {
            throw new ResponseStatusException(
                    HttpStatus.TOO_MANY_REQUESTS, "too many failed login attempts - try again later");
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
