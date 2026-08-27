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

    public AuthenticationService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            JwtService jwtService,
            LoginAttemptLimiter loginAttemptLimiter,
            @Value("${bloodhound.jwt.refresh-token-ttl-days:30}") long refreshTokenTtlDays) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.loginAttemptLimiter = loginAttemptLimiter;
        this.refreshTokenTtl = Duration.ofDays(refreshTokenTtlDays);
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
        return issueTokens(user);
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

        User user = userRepository
                .findById(existing.userId())
                .filter(u -> "ACTIVE".equals(u.status()))
                .orElseThrow(InvalidRefreshTokenException::new);

        refreshTokenRepository.revoke(existing.id());
        AuthResult result = issueTokens(user);
        refreshTokenRepository.linkReplacement(existing.id(), result.refreshTokenId());
        return result;
    }

    public void logout(String rawRefreshToken) {
        refreshTokenRepository.findActive(hash(rawRefreshToken)).ifPresent(t -> refreshTokenRepository.revoke(t.id()));
    }

    /** Public so the SAML success handler (auth.sso) can mint real tokens the same way local login does. */
    public AuthResult issueTokens(User user) {
        String accessToken = jwtService.issueAccessToken(user.id(), user.organizationId(), user.role(), user.email());

        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String rawRefreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        UUID refreshTokenId = UUID.randomUUID();
        refreshTokenRepository.insert(
                refreshTokenId, user.id(), hash(rawRefreshToken), Timestamp.from(Instant.now().plus(refreshTokenTtl)));

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
