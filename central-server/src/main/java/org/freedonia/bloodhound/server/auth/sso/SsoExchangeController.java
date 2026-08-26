package org.freedonia.bloodhound.server.auth.sso;

import org.freedonia.bloodhound.server.auth.dto.AuthResponse;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
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
 */
@RestController
@RequestMapping("/api/v1/auth/sso")
public class SsoExchangeController {

    public record ExchangeRequest(String code) {}

    private final SsoHandoffCodeRepository handoffCodeRepository;
    private final UserRepository userRepository;

    public SsoExchangeController(SsoHandoffCodeRepository handoffCodeRepository, UserRepository userRepository) {
        this.handoffCodeRepository = handoffCodeRepository;
        this.userRepository = userRepository;
    }

    @PostMapping("/exchange")
    public AuthResponse exchange(@RequestBody ExchangeRequest request) {
        SsoHandoffCodeRepository.Result result = handoffCodeRepository
                .consume(request.code())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "invalid, expired, or already-used SSO code"));
        UserSummary user = userRepository
                .findById(result.userId())
                .map(UserSummary::from)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "user no longer exists"));
        return new AuthResponse(result.accessToken(), result.expiresIn(), result.refreshToken(), user);
    }
}
