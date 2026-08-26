package org.freedonia.bloodhound.server.auth.sso;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Short-lived, single-use handoff between a successful SAML browser redirect
 * and webui's backend, which exchanges the opaque code for the real
 * access/refresh tokens server-side - see V18's migration comment for why
 * (never put real tokens in a redirect URL).
 */
@Repository
public class SsoHandoffCodeRepository {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Duration TTL = Duration.ofSeconds(60);

    private static final RowMapper<Result> ROW_MAPPER = (rs, rowNum) -> new Result(
            java.util.UUID.fromString(rs.getString("user_id")),
            rs.getString("access_token"),
            rs.getLong("expires_in"),
            rs.getString("refresh_token"));

    private final JdbcTemplate jdbc;

    public SsoHandoffCodeRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record Result(java.util.UUID userId, String accessToken, long expiresIn, String refreshToken) {}

    public String create(java.util.UUID userId, String accessToken, long expiresIn, String refreshToken) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        jdbc.update(
                "INSERT INTO sso_handoff_codes (code, user_id, access_token, expires_in, refresh_token, expires_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?)",
                code,
                userId,
                accessToken,
                expiresIn,
                refreshToken,
                Timestamp.from(Instant.now().plus(TTL)));
        return code;
    }

    /**
     * Single-use: deletes on lookup regardless of outcome, so a replay of the same
     * code (whether already-consumed or forged-but-guessed) always finds nothing.
     */
    public Optional<Result> consume(String code) {
        Optional<Result> result = jdbc.query(
                        "SELECT * FROM sso_handoff_codes WHERE code = ? AND expires_at > now()", ROW_MAPPER, code)
                .stream()
                .findFirst();
        jdbc.update("DELETE FROM sso_handoff_codes WHERE code = ?", code);
        return result;
    }
}
