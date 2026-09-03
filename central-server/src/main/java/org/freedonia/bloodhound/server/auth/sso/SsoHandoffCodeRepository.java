package org.freedonia.bloodhound.server.auth.sso;

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
 * Short-lived, single-use handoff between a successful SAML browser redirect
 * and webui's backend, which exchanges the opaque code for the real
 * access/refresh tokens server-side - see V18's migration comment for why
 * (never put real tokens in a redirect URL).
 *
 * <p>A security review found the original version of this stored the real, unhashed access and
 * refresh tokens here - minted ahead of time by SamlAuthenticationSuccessHandler, then persisted
 * in plaintext until consumed. Unlike refresh_tokens (SHA-256 hashed at rest) and every other
 * credential table in this app, that made this the one place a real, immediately-usable,
 * up-to-90-day credential sat in plaintext, readable by anyone with DB or backup access - and,
 * since {@link #consume} can only ever delete a still-unexpired row (see its own javadoc), an
 * abandoned SSO attempt (a closed tab, a network blip) left its row - and its plaintext tokens -
 * sitting there forever with nothing else in the codebase ever referencing this table to clean it
 * up. Tokens are now minted only at exchange time (see SsoExchangeController), not stored here at
 * all - this table holds only the opaque code and which user it's for, the same "handle, not the
 * real thing" shape refresh_tokens/api_keys/scim_tokens already use. The second half of that same
 * finding - nothing ever swept expired, abandoned rows - is closed by {@link #sweepExpired} below,
 * independent of the plaintext-token fix (an abandoned row is still clutter worth cleaning up even
 * though it no longer carries a real secret).
 */
@Repository
public class SsoHandoffCodeRepository {

    private static final Logger log = LoggerFactory.getLogger(SsoHandoffCodeRepository.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Duration TTL = Duration.ofSeconds(60);

    private final JdbcTemplate jdbc;

    public SsoHandoffCodeRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public String create(UUID userId) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        jdbc.update(
                "INSERT INTO sso_handoff_codes (code, user_id, expires_at) VALUES (?, ?, ?)",
                code,
                userId,
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
     *
     * <p>{@code WHERE expires_at > now()} means an already-expired row is never matched here -
     * that's deliberate (an expired code must never be honored, even if still present) - but it
     * also means this method can never be the thing that cleans up an abandoned, expired row.
     * {@link #sweepExpired} is the separate cleanup path for that.
     */
    public Optional<UUID> consume(String code) {
        return jdbc.query(
                        "DELETE FROM sso_handoff_codes WHERE code = ? AND expires_at > now() RETURNING user_id",
                        (rs, rowNum) -> UUID.fromString(rs.getString("user_id")),
                        code)
                .stream()
                .findFirst();
    }

    /**
     * A security review found expired-but-unconsumed rows (an abandoned SSO attempt - a closed
     * tab, a network blip between the SAML redirect and webui calling exchange) were never
     * deleted by anything: consume()'s own WHERE clause structurally excludes them, and no other
     * code in this app ever referenced this table. Runs independently of any real login - a
     * scheduled sweep, not "clean up on next successful login," so abandoned rows don't linger
     * indefinitely just because nobody happens to log in again.
     */
    @Scheduled(fixedDelayString = "${bloodhound.sso.handoff-sweep-interval-ms:300000}")
    public void sweepExpired() {
        int deleted = jdbc.update("DELETE FROM sso_handoff_codes WHERE expires_at <= now()");
        if (deleted > 0) {
            log.debug("swept {} expired SSO handoff code(s)", deleted);
        }
    }
}
