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
     * Single-use: a single atomic {@code DELETE ... RETURNING}, not a SELECT followed by a
     * separate DELETE - a security review caught that the two-statement form let a raced
     * double-exchange of the same code (two requests landing between the SELECT and the DELETE)
     * both read the row and both succeed, defeating the single-use guarantee this class exists
     * for. A single DELETE is atomic: Postgres serializes concurrent DELETEs against the same
     * row via its normal row-level locking, so only ever one caller can actually delete (and
     * therefore receive) a given code's row - a second, concurrent consume() for the same code
     * deletes zero rows and correctly gets Optional.empty(), the same as an already-consumed or
     * forged-but-guessed code always did.
     */
    public Optional<Result> consume(String code) {
        return jdbc.query(
                        "DELETE FROM sso_handoff_codes WHERE code = ? AND expires_at > now() RETURNING *",
                        ROW_MAPPER,
                        code)
                .stream()
                .findFirst();
    }
}
