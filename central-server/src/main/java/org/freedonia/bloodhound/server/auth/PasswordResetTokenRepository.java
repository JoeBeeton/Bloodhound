package org.freedonia.bloodhound.server.auth;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Repository;

/**
 * Short-lived, single-use token behind self-serve "forgot password" (see AuthController). Same
 * shape and same race-safety reasoning as {@code auth.sso.SsoHandoffCodeRepository} - only the
 * TTL differs (an hour, not 60 seconds: this one is emailed to a human to act on, not exchanged
 * by a browser mid-redirect).
 */
@Repository
public class PasswordResetTokenRepository {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetTokenRepository.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Duration TTL = Duration.ofHours(1);

    private final JdbcTemplate jdbc;

    public PasswordResetTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public String create(UUID userId) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        jdbc.update(
                "INSERT INTO password_reset_tokens (code, user_id, expires_at) VALUES (?, ?, ?)",
                code,
                userId,
                Timestamp.from(Instant.now().plus(TTL)));
        return code;
    }

    /**
     * Single-use: one atomic {@code DELETE ... RETURNING}, not a SELECT then a separate DELETE -
     * same reasoning as SsoHandoffCodeRepository#consume's own javadoc, so a raced double-submit
     * of the same token can't both succeed. {@code WHERE expires_at > now()} means an expired row
     * is never matched (and is therefore never the thing this method cleans up - see
     * {@link #sweepExpired} for that).
     */
    public Optional<UUID> consume(String code) {
        return jdbc.query(
                        "DELETE FROM password_reset_tokens WHERE code = ? AND expires_at > now() RETURNING user_id",
                        (rs, rowNum) -> UUID.fromString(rs.getString("user_id")),
                        code)
                .stream()
                .findFirst();
    }

    /** Cleans up abandoned, expired, never-consumed rows (an ignored email, a stale tab) - same gap SsoHandoffCodeRepository#sweepExpired closes for its own table. */
    @Scheduled(fixedDelayString = "${bloodhound.sso.handoff-sweep-interval-ms:300000}")
    public void sweepExpired() {
        int deleted = jdbc.update("DELETE FROM password_reset_tokens WHERE expires_at <= now()");
        if (deleted > 0) {
            log.debug("swept {} expired password reset token(s)", deleted);
        }
    }
}
