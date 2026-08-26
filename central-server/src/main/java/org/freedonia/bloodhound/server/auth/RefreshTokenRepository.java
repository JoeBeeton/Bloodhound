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

    public void revoke(UUID id) {
        jdbc.update("UPDATE refresh_tokens SET revoked_at = now() WHERE id = ?", id);
    }

    public void linkReplacement(UUID oldId, UUID newId) {
        jdbc.update("UPDATE refresh_tokens SET replaced_by_token_id = ? WHERE id = ?", newId, oldId);
    }
}
