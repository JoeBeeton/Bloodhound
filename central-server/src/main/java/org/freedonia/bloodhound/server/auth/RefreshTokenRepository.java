package org.freedonia.bloodhound.server.auth;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRepository {

    private static final RowMapper<RefreshToken> ROW_MAPPER = (rs, rowNum) -> new RefreshToken(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("user_id")),
            rs.getString("token_hash"),
            rs.getTimestamp("expires_at").toInstant(),
            rs.getTimestamp("revoked_at") != null ? rs.getTimestamp("revoked_at").toInstant() : null,
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("session_started_at").toInstant());

    private final JdbcTemplate jdbc;

    public RefreshTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * @param sessionStartedAt fixed for the whole rotation lineage - a fresh login passes {@code
     *     now()}, a rotation (see AuthenticationService#refresh) passes the token being replaced's
     *     own sessionStartedAt through unchanged, so it never resets on activity.
     */
    public void insert(UUID id, UUID userId, String tokenHash, Timestamp expiresAt, Timestamp sessionStartedAt) {
        jdbc.update(
                "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, session_started_at) VALUES (?, ?, ?, ?, ?)",
                id,
                userId,
                tokenHash,
                expiresAt,
                sessionStartedAt);
    }

    /** Returns the token only if it exists, is unrevoked, and unexpired. */
    public Optional<RefreshToken> findActive(String tokenHash) {
        return jdbc.query("SELECT * FROM refresh_tokens WHERE token_hash = ?", ROW_MAPPER, tokenHash).stream()
                .findFirst()
                .filter(t -> t.revokedAt() == null && t.expiresAt().isAfter(Instant.now()));
    }

    /**
     * Unlike {@link #findActive}, returns the row regardless of revoked/expired status - the
     * refresh flow needs to tell "this exact token was already rotated away" (reuse of a
     * revoked-but-otherwise-valid token, the standard OAuth-refresh theft signal - see {@link
     * #revokeLineageFrom}) apart from "no such token ever existed" or "expired", which {@link
     * #findActive} collapses into a single empty Optional.
     */
    public Optional<RefreshToken> findByHash(String tokenHash) {
        return jdbc.query("SELECT * FROM refresh_tokens WHERE token_hash = ?", ROW_MAPPER, tokenHash).stream()
                .findFirst();
    }

    public void revoke(UUID id) {
        jdbc.update("UPDATE refresh_tokens SET revoked_at = now() WHERE id = ?", id);
    }

    /**
     * A security review found that changing your password left every other still-active refresh
     * token (and the httpOnly cookie it lives in, on whatever other device/browser holds it)
     * completely untouched - the primary self-remediation action a user takes when they suspect
     * their account is compromised previously did nothing to actually end an attacker's existing
     * session. Called from UserSelfController#changePassword.
     */
    public void revokeAllForUser(UUID userId) {
        jdbc.update("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ? AND revoked_at IS NULL", userId);
    }

    /**
     * "Log out of all other devices" - revokes every other active refresh token for this user
     * while leaving the caller's own current session (identified by its token hash) untouched, so
     * the request that triggered this doesn't also lock its own caller out. See
     * UserSelfController#logoutOtherSessions.
     */
    public void revokeAllForUserExceptHash(UUID userId, String exceptTokenHash) {
        jdbc.update(
                "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ? AND token_hash != ? AND revoked_at IS NULL",
                userId,
                exceptTokenHash);
    }

    /**
     * How many active sessions this user has right now (including whichever one is asking), for
     * the "you have N active sessions" UI count - deliberately takes no token of its own to
     * exclude (unlike {@link #revokeAllForUserExceptHash}), so this can be a plain GET with no
     * sensitive value in a query string that would otherwise end up in access logs.
     */
    public int countActiveForUser(UUID userId) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL AND expires_at > now()",
                Integer.class,
                userId);
        return count != null ? count : 0;
    }

    /**
     * Conditional revoke that reports whether THIS call was actually the one that flipped
     * {@code revoked_at} - used by the refresh-rotation path to close a race a security review
     * found: AuthenticationService#refresh previously read the token, checked {@code revokedAt()
     * == null}, and only revoked it several lines later as a separate statement, so two
     * concurrent refreshes of the same still-valid token could both pass the check before either
     * committed its revoke, forking the session into two valid lineages instead of triggering the
     * theft response. The {@code WHERE revoked_at IS NULL} condition makes the UPDATE itself the
     * point of truth: whichever caller's statement actually executes first wins (returns true),
     * and the loser's UPDATE affects zero rows (returns false) because Postgres serializes
     * concurrent UPDATEs to the same row via row-level locking - there is no window between
     * "check" and "act" left to race, because there's only one statement.
     */
    public boolean tryRevoke(UUID id) {
        int updated = jdbc.update("UPDATE refresh_tokens SET revoked_at = now() WHERE id = ? AND revoked_at IS NULL", id);
        return updated > 0;
    }

    public void linkReplacement(UUID oldId, UUID newId) {
        jdbc.update("UPDATE refresh_tokens SET replaced_by_token_id = ? WHERE id = ?", newId, oldId);
    }

    /**
     * Refresh-token reuse/theft hardening: rotation already revokes the OLD token on every
     * refresh (see AuthenticationService#refresh), but replaying that now-revoked token was
     * previously just rejected on its own - not treated as a compromise signal. A revoked token
     * being presented again means someone (attacker or the legitimate holder, we can't tell
     * which) has a copy that's no longer the current one, which happens either because it was
     * stolen and both parties are now racing to use it, or because it's genuinely already spent.
     * Standard OAuth-refresh-rotation hardening treats this as theft and revokes the whole
     * lineage forward from the reused token - including whichever token IS currently active -
     * so neither party can keep going on this session; the legitimate user simply has to log in
     * again. Walks {@code replaced_by_token_id} forward via a recursive CTE rather than the
     * application looping token-by-token, so the whole chain is revoked in one atomic statement
     * regardless of how many times the session had already rotated.
     */
    public void revokeLineageFrom(UUID id) {
        jdbc.update(
                """
                WITH RECURSIVE lineage AS (
                    SELECT id, replaced_by_token_id FROM refresh_tokens WHERE id = ?
                    UNION ALL
                    SELECT rt.id, rt.replaced_by_token_id
                    FROM refresh_tokens rt
                    JOIN lineage l ON rt.id = l.replaced_by_token_id
                )
                UPDATE refresh_tokens SET revoked_at = now()
                WHERE id IN (SELECT id FROM lineage) AND revoked_at IS NULL
                """,
                id);
    }
}
