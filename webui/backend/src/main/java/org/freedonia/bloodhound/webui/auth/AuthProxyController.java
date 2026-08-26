package org.freedonia.bloodhound.webui.auth;

import java.time.Duration;
import org.freedonia.bloodhound.webui.auth.dto.ClientAuthResponse;
import org.freedonia.bloodhound.webui.auth.dto.LoginRequest;
import org.freedonia.bloodhound.webui.auth.dto.RefreshTokenRequest;
import org.freedonia.bloodhound.webui.auth.dto.SsoExchangeRequest;
import org.freedonia.bloodhound.webui.auth.dto.UpstreamAuthResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * The only backend logic webui carries: proxy auth calls to central-server
 * and turn its raw refresh token into an HttpOnly cookie, so the browser
 * only ever sees a short-lived access token in the JSON response body. A
 * general /api/** data passthrough is deliberately not built yet - it lands
 * whenever the dashboard needs its first real central-server data call.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthProxyController {

    private static final String REFRESH_COOKIE = "bh_refresh";
    private static final Duration REFRESH_COOKIE_MAX_AGE = Duration.ofDays(30);

    private final RestClient centralServerClient;

    public AuthProxyController(RestClient centralServerClient) {
        this.centralServerClient = centralServerClient;
    }

    @PostMapping("/login")
    public ResponseEntity<ClientAuthResponse> login(@RequestBody LoginRequest request) {
        try {
            UpstreamAuthResponse upstream = centralServerClient
                    .post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(UpstreamAuthResponse.class);
            return respondWithSessionCookie(upstream);
        } catch (HttpClientErrorException e) {
            // Was previously HttpClientErrorException.Unauthorized only, which
            // silently turned any *other* 4xx central-server could return
            // (e.g. 429 from the login rate limiter added in the security
            // review) into an opaque 500 here - found by actually testing the
            // rate limiter against the live system, not assumed. Passing the
            // real status straight through is correct for every 4xx central-
            // server sends from this endpoint, not just 401.
            return ResponseEntity.status(e.getStatusCode()).build();
        }
    }

    /**
     * Called by the frontend's /sso/callback route right after a SAML login
     * redirect lands with a one-time code in the URL - exchanges it
     * server-side for the real tokens (never exposed in the URL itself, see
     * central-server's SsoHandoffCodeRepository) and sets the same HttpOnly
     * refresh cookie a normal /login does, so post-SSO the browser is in an
     * identical state to a local login.
     */
    @PostMapping("/sso/exchange")
    public ResponseEntity<ClientAuthResponse> ssoExchange(@RequestBody SsoExchangeRequest request) {
        try {
            UpstreamAuthResponse upstream = centralServerClient
                    .post()
                    .uri("/api/v1/auth/sso/exchange")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(UpstreamAuthResponse.class);
            return respondWithSessionCookie(upstream);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).build();
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ClientAuthResponse> refresh(
            @CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try {
            UpstreamAuthResponse upstream = centralServerClient
                    .post()
                    .uri("/api/v1/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new RefreshTokenRequest(refreshToken))
                    .retrieve()
                    .body(UpstreamAuthResponse.class);
            return respondWithSessionCookie(upstream);
        } catch (HttpClientErrorException.Unauthorized e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.SET_COOKIE, clearCookie().toString())
                    .build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken) {
        if (refreshToken != null) {
            try {
                centralServerClient
                        .post()
                        .uri("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(new RefreshTokenRequest(refreshToken))
                        .retrieve()
                        .toBodilessEntity();
            } catch (Exception ignored) {
                // best-effort revoke; the cookie is cleared client-side regardless
            }
        }
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, clearCookie().toString())
                .build();
    }

    private ResponseEntity<ClientAuthResponse> respondWithSessionCookie(UpstreamAuthResponse upstream) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, upstream.refreshToken())
                .httpOnly(true)
                .secure(false) // TODO: true once webui is served behind TLS in production
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(REFRESH_COOKIE_MAX_AGE)
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ClientAuthResponse.from(upstream));
    }

    private ResponseCookie clearCookie() {
        return ResponseCookie.from(REFRESH_COOKIE, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(0)
                .build();
    }
}
