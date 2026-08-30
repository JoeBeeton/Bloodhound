package org.freedonia.bloodhound.server.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    // Every placeholder value .env.example has ever shipped for this key -
    // if the live value is still one of these, anyone who has ever seen this
    // repository's example config can forge valid access tokens for any
    // user/org/role. Deliberately a startup WARNING, not a hard fail: this
    // codebase is running as a live system with a real user on it right
    // now, and a fail-fast here would take it down mid-use the moment this
    // fix deploys, for a config change only the operator (not this code)
    // should make. See SECURITY_NOTES.md. Old values are kept here
    // (rather than replaced) so a deployment seeded before .env.example's
    // placeholder text changed still gets caught.
    private static final Set<String> KNOWN_PLACEHOLDER_KEYS =
            Set.of("change-me-dev-only-not-a-real-secret", "<generate-with-openssl-rand-base64-48>");

    private final SecretKey signingKey;
    private final Duration accessTokenTtl;
    private final boolean signingKeyIsPlaceholder;

    public JwtService(
            @Value("${bloodhound.jwt.signing-key}") String signingKeySecret,
            @Value("${bloodhound.jwt.access-token-ttl-minutes:15}") long accessTokenTtlMinutes) {
        if (signingKeySecret == null || signingKeySecret.getBytes(StandardCharsets.UTF_8).length < 32) {
            // Fail fast at startup rather than issuing weak/unverifiable tokens.
            throw new IllegalStateException(
                    "JWT_SIGNING_KEY must be set and at least 32 bytes long (HS256 requires a >=256-bit key)");
        }
        this.signingKeyIsPlaceholder = KNOWN_PLACEHOLDER_KEYS.contains(signingKeySecret);
        if (signingKeyIsPlaceholder) {
            log.warn(
                    "SECURITY: JWT_SIGNING_KEY is still the example placeholder from .env.example. Anyone who has "
                            + "seen that file can forge valid login tokens for any user in this deployment. Rotate "
                            + "it to a real random secret (e.g. `openssl rand -base64 48`) before this is exposed "
                            + "beyond a trusted local machine - note that rotating it invalidates every currently "
                            + "logged-in session, so pick a deliberate moment to do it.");
        }
        this.signingKey = Keys.hmacShaKeyFor(signingKeySecret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenTtl = Duration.ofMinutes(accessTokenTtlMinutes);
    }

    /**
     * A security review found this misconfiguration only ever surfaced as a startup log line -
     * an admin using the UI had no way to discover it short of reading server logs. Exposed here
     * so SecurityStatusController can surface it as a banner no admin can miss.
     */
    public boolean isSigningKeyPlaceholder() {
        return signingKeyIsPlaceholder;
    }

    public String issueAccessToken(UUID userId, UUID organizationId, String role, String email) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("org", organizationId.toString())
                .claim("role", role)
                .claim("email", email)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTokenTtl)))
                .signWith(signingKey)
                .compact();
    }

    public long accessTokenTtlSeconds() {
        return accessTokenTtl.toSeconds();
    }

    public Claims parseAndValidate(String token) throws JwtException {
        return Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();
    }
}
