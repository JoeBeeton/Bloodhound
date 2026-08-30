package org.freedonia.bloodhound.webui.auth;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import org.freedonia.bloodhound.webui.auth.dto.ClientAuthResponse;
import org.freedonia.bloodhound.webui.auth.dto.LoginRequest;
import org.freedonia.bloodhound.webui.auth.dto.LogoutOtherSessionsRequest;
import org.freedonia.bloodhound.webui.auth.dto.RefreshTokenRequest;
import org.freedonia.bloodhound.webui.auth.dto.SsoExchangeRequest;
import org.freedonia.bloodhound.webui.auth.dto.UpstreamAuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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

    private static final Logger log = LoggerFactory.getLogger(AuthProxyController.class);
    private static final String REFRESH_COOKIE = "bh_refresh";
    private static final Duration REFRESH_COOKIE_MAX_AGE = Duration.ofDays(30);

    private final RestClient centralServerClient;

    public AuthProxyController(RestClient centralServerClient) {
        this.centralServerClient = centralServerClient;
    }

    @PostMapping("/login")
    public ResponseEntity<ClientAuthResponse> login(@RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        try {
            UpstreamAuthResponse upstream = centralServerClient
                    .post()
                    .uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(UpstreamAuthResponse.class);
            return respondWithSessionCookie(upstream, servletRequest);
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
    public ResponseEntity<ClientAuthResponse> ssoExchange(
            @RequestBody SsoExchangeRequest request, HttpServletRequest servletRequest) {
        try {
            UpstreamAuthResponse upstream = centralServerClient
                    .post()
                    .uri("/api/v1/auth/sso/exchange")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(UpstreamAuthResponse.class);
            return respondWithSessionCookie(upstream, servletRequest);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).build();
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ClientAuthResponse> refresh(
            @CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken, HttpServletRequest servletRequest) {
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
            return respondWithSessionCookie(upstream, servletRequest);
        } catch (HttpClientErrorException.Unauthorized e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.SET_COOKIE, clearCookie(servletRequest).toString())
                    .build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken, HttpServletRequest servletRequest) {
        if (refreshToken != null) {
            try {
                centralServerClient
                        .post()
                        .uri("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(new RefreshTokenRequest(refreshToken))
                        .retrieve()
                        .toBodilessEntity();
            } catch (Exception e) {
                // Best-effort revoke; the cookie is cleared client-side regardless (the user must
                // not stay stuck in a "logged in" UI state over a transient backend failure). A
                // security review noted this was previously silently swallowed, though: on
                // failure here the token is NOT actually revoked server-side and stays valid until
                // its natural expiry even though the user believes they've logged out - logging it
                // at least makes that residual-session window visible to operators instead of
                // disappearing entirely.
                log.warn("failed to revoke refresh token on logout - token remains valid until natural expiry", e);
            }
        }
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, clearCookie(servletRequest).toString())
                .build();
    }

    /**
     * "Log out of all other devices" - needs both the httpOnly refresh cookie (webui/backend is
     * the only party that can read it - see the class javadoc) AND the caller's own bearer access
     * token, forwarded through to central-server's identity check. Unlike every other endpoint
     * here, this one requires an authenticated caller - the plain /api/v1/** passthrough
     * (ApiProxyController) already forwards Authorization transparently for ordinary data calls,
     * but it never sees this cookie (its path is scoped to /api/auth), so this one action needs
     * its own dedicated route here instead.
     */
    @PostMapping("/logout-others")
    public ResponseEntity<Void> logoutOtherSessions(
            @CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (refreshToken == null || authorization == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try {
            centralServerClient
                    .post()
                    .uri("/api/v1/users/me/sessions/logout-others")
                    .header(HttpHeaders.AUTHORIZATION, authorization)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new LogoutOtherSessionsRequest(refreshToken))
                    .retrieve()
                    .toBodilessEntity();
            return ResponseEntity.noContent().build();
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).build();
        }
    }

    private ResponseEntity<ClientAuthResponse> respondWithSessionCookie(
            UpstreamAuthResponse upstream, HttpServletRequest servletRequest) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, upstream.refreshToken())
                .httpOnly(true)
                .secure(isSecure(servletRequest))
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(REFRESH_COOKIE_MAX_AGE)
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(ClientAuthResponse.from(upstream));
    }

    private ResponseCookie clearCookie(HttpServletRequest servletRequest) {
        return ResponseCookie.from(REFRESH_COOKIE, "")
                .httpOnly(true)
                .secure(isSecure(servletRequest))
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(0)
                .build();
    }

    /**
     * Was hardcoded {@code false} unconditionally (a security review flagged this: a 30-day
     * httpOnly cookie sniffable over any plaintext hop unless someone remembered to hand-edit it
     * before prod). Derives the flag from the actual request instead, so it does the right thing
     * with no config to remember: plain HTTP in local dev (docker-compose exposes services
     * directly, unencrypted) correctly gets an unmarked cookie, and a real deployment gets a
     * Secure one automatically - either because webui itself terminates TLS, or because a
     * fronting reverse proxy does and forwards {@code X-Forwarded-Proto: https}, which {@code
     * HttpServletRequest#isSecure()} reflects once the deployer enables Spring Boot's
     * forward-headers support (server.forward-headers-strategy) for their proxy - that trust
     * decision belongs to the deployer's own proxy config, not something this app can safely
     * assume.
     */
    private static boolean isSecure(HttpServletRequest servletRequest) {
        return servletRequest.isSecure();
    }
}
