package org.freedonia.bloodhound.server.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final LoginAttemptLimiter loginAttemptLimiter;
    private final Duration refreshTokenTtl;
    private final Duration absoluteMaxSessionDuration;

    public AuthenticationService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            JwtService jwtService,
            LoginAttemptLimiter loginAttemptLimiter,
            @Value("${bloodhound.jwt.refresh-token-ttl-days:30}") long refreshTokenTtlDays,
            @Value("${bloodhound.jwt.refresh-token-absolute-max-days:90}") long absoluteMaxSessionDays) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.loginAttemptLimiter = loginAttemptLimiter;
        this.refreshTokenTtl = Duration.ofDays(refreshTokenTtlDays);
        this.absoluteMaxSessionDuration = Duration.ofDays(absoluteMaxSessionDays);
    }

    public AuthResult login(String email, String password) {
        loginAttemptLimiter.checkAllowed(email);
        AuthenticatedUserPrincipal principal;
        try {
            var authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            principal = (AuthenticatedUserPrincipal) authentication.getPrincipal();
        } catch (AuthenticationException e) {
            loginAttemptLimiter.recordFailure(email);
            // Deliberately generic - don't leak whether the email exists.
            throw new InvalidCredentialsException();
        }
        loginAttemptLimiter.recordSuccess(email);
        User user = principal.user();
        userRepository.touchLastLogin(user.id());
        return issueTokens(user, Instant.now());
    }

    public AuthResult refresh(String rawRefreshToken) {
        RefreshToken existing =
                refreshTokenRepository.findByHash(hash(rawRefreshToken)).orElseThrow(InvalidRefreshTokenException::new);

        // Reuse of an already-revoked token (rotation revokes the old token on every refresh -
        // see below) is the standard OAuth-refresh theft signal: someone is presenting a token
        // that's no longer current, meaning either it was stolen and the attacker and the
        // legitimate holder are now both trying to use this session, or it's simply already
        // spent. Either way, the safe response is to revoke the whole lineage - including
        // whichever token IS currently active - and force a real re-login, not just reject this
        // one request. Checked before the expiry check below so an attacker can't distinguish
        // "revoked" from "expired" by timing/response - both end up InvalidRefreshTokenException.
        if (existing.revokedAt() != null) {
            refreshTokenRepository.revokeLineageFrom(existing.id());
            throw new InvalidRefreshTokenException();
        }
        if (existing.expiresAt().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException();
        }
        // A security review found the sliding 30-day TTL (reset on every login AND every refresh)
        // had no ceiling independent of activity - a token used at least once a month never
        // naturally expired. sessionStartedAt is fixed at the lineage's true origin (propagated
        // unchanged through every rotation, see issueTokens below), so this check holds
        // regardless of how recently the token was last used - forcing a real re-login past the
        // absolute cap even for an actively-used session.
        if (existing.sessionStartedAt().plus(absoluteMaxSessionDuration).isBefore(Instant.now())) {
            refreshTokenRepository.revokeLineageFrom(existing.id());
            throw new InvalidRefreshTokenException();
        }

        User user = userRepository
                .findById(existing.userId())
                .filter(u -> "ACTIVE".equals(u.status()))
                .orElseThrow(InvalidRefreshTokenException::new);

        // tryRevoke, not the plain unconditional revoke: a security review found that reading
        // revokedAt() above and only revoking here as a separate statement left a genuine
        // rotation race - two concurrent refresh() calls for the same still-valid token could
        // both pass the check above before either committed its revoke, both proceeding to mint
        // a child token and forking the session instead of one of them being rejected. tryRevoke
        // is the atomic point of truth: only the caller whose UPDATE actually flips revoked_at
        // (there can be only one, since Postgres serializes concurrent UPDATEs to the same row)
        // gets to rotate; the loser is treated exactly like an already-revoked replay, since from
        // its perspective that's exactly what happened a moment too late to observe directly.
        if (!refreshTokenRepository.tryRevoke(existing.id())) {
            refreshTokenRepository.revokeLineageFrom(existing.id());
            throw new InvalidRefreshTokenException();
        }
        AuthResult result = issueTokens(user, existing.sessionStartedAt());
        refreshTokenRepository.linkReplacement(existing.id(), result.refreshTokenId());
        return result;
    }

    public void logout(String rawRefreshToken) {
        refreshTokenRepository.findActive(hash(rawRefreshToken)).ifPresent(t -> refreshTokenRepository.revoke(t.id()));
    }

    /**
     * Public so the SAML success handler (auth.sso) can mint real tokens the same way local login
     * does - always a fresh session (sessionStartedAt = now()), since SAML doesn't have a
     * rotation concept of its own to propagate a lineage origin through.
     */
    public AuthResult issueTokens(User user) {
        return issueTokens(user, Instant.now());
    }

    private AuthResult issueTokens(User user, Instant sessionStartedAt) {
        String accessToken = jwtService.issueAccessToken(user.id(), user.organizationId(), user.role(), user.email());

        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String rawRefreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        UUID refreshTokenId = UUID.randomUUID();
        refreshTokenRepository.insert(
                refreshTokenId,
                user.id(),
                hash(rawRefreshToken),
                Timestamp.from(Instant.now().plus(refreshTokenTtl)),
                Timestamp.from(sessionStartedAt));

        return new AuthResult(
                accessToken,
                jwtService.accessTokenTtlSeconds(),
                rawRefreshToken,
                refreshTokenId,
                UserSummary.from(user));
    }

    private static String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
