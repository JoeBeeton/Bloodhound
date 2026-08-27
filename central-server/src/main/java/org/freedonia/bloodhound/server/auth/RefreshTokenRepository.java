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
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public RefreshTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(UUID id, UUID userId, String tokenHash, Timestamp expiresAt) {
        jdbc.update(
                "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
                id,
                userId,
                tokenHash,
                expiresAt);
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
