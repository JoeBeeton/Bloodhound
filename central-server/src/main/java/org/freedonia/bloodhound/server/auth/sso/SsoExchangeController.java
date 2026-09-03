package org.freedonia.bloodhound.server.auth.sso;

import java.util.UUID;
import org.freedonia.bloodhound.server.auth.AuthenticationService;
import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Falls under the existing /api/v1/auth/** permitAll matcher in
 * SecurityConfig - no JWT exists yet at the point webui calls this (that's
 * the whole point of the exchange). Same trust model as /login and /refresh:
 * a plain unauthenticated API endpoint, not something reserved for webui's
 * own proxy specifically.
 *
 * <p>A security review found this used to just read back real tokens SamlAuthenticationSuccessHandler
 * had already minted and stored in sso_handoff_codes in plaintext. Tokens are minted here, at
 * exchange time, instead - see SsoHandoffCodeRepository's own javadoc for the full reasoning;
 * the handoff code now carries only which user this exchange is for.
 */
@RestController
@RequestMapping("/api/v1/auth/sso")
public class SsoExchangeController {

    public record ExchangeRequest(String code) {}

    private final SsoHandoffCodeRepository handoffCodeRepository;
    private final UserRepository userRepository;
    private final AuthenticationService authenticationService;

    public SsoExchangeController(
            SsoHandoffCodeRepository handoffCodeRepository,
            UserRepository userRepository,
            AuthenticationService authenticationService) {
        this.handoffCodeRepository = handoffCodeRepository;
        this.userRepository = userRepository;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/exchange")
    public AuthResponse exchange(@RequestBody ExchangeRequest request) {
        UUID userId = handoffCodeRepository
                .consume(request.code())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "invalid, expired, or already-used SSO code"));
        User user = userRepository
                .findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "user no longer exists"));
        return AuthResponse.from(authenticationService.issueTokens(user));
    }
}
