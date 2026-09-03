package org.freedonia.bloodhound.server.apikey;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Mirrors auth.WorkerCredentialRepository/scim.ScimTokenRepository's hash-at-rest pattern. */
@Repository
public class ApiKeyRepository {

    private static final RowMapper<ApiKey> ROW_MAPPER = (rs, rowNum) -> new ApiKey(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            UUID.fromString(rs.getString("created_by_user_id")),
            rs.getString("label"),
            rs.getString("key_prefix"),
            rs.getString("key_hash"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("expires_at").toInstant(),
            rs.getTimestamp("last_used_at") != null ? rs.getTimestamp("last_used_at").toInstant() : null,
            rs.getTimestamp("revoked_at") != null ? rs.getTimestamp("revoked_at").toInstant() : null);

    private final JdbcTemplate jdbc;

    public ApiKeyRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Looked up on (potentially) every API-key-authenticated request, so this stays a single
     * indexed hash lookup - active/expiry filtering happens in Java against the one returned
     * row rather than in SQL, matching the existing WorkerCredentialRepository/ScimTokenRepository
     * pattern, since a hash lookup only ever returns 0 or 1 rows.
     */
    public Optional<ApiKey> findByKeyHash(String keyHash) {
        return jdbc.query("SELECT * FROM api_keys WHERE key_hash = ?", ROW_MAPPER, keyHash).stream()
                .findFirst();
    }

    public List<ApiKey> findByCreatedByUser(UUID userId) {
        return jdbc.query(
                "SELECT * FROM api_keys WHERE created_by_user_id = ? ORDER BY created_at DESC", ROW_MAPPER, userId);
    }

    public List<ApiKey> findByOrganization(UUID organizationId) {
        return jdbc.query(
                "SELECT * FROM api_keys WHERE organization_id = ? ORDER BY created_at DESC",
                ROW_MAPPER,
                organizationId);
    }

    public ApiKey insert(
            UUID organizationId, UUID createdByUserId, String label, String keyPrefix, String keyHash, Instant expiresAt) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO api_keys (id, organization_id, created_by_user_id, label, key_prefix, key_hash, expires_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?)",
                id,
                organizationId,
                createdByUserId,
                label,
                keyPrefix,
                keyHash,
                java.sql.Timestamp.from(expiresAt));
        return jdbc.query("SELECT * FROM api_keys WHERE id = ?", ROW_MAPPER, id).get(0);
    }

    /** Best-effort audit trail for "when was this key last actually used" - failures here must never fail the request it's auditing. */
    public void touchLastUsed(UUID id) {
        jdbc.update("UPDATE api_keys SET last_used_at = now() WHERE id = ?", id);
    }

    /**
     * Revokes only if the key belongs to the given user, OR the caller is an org admin
     * revoking any key within their own org (see ApiKeyController) - callers must not be
     * able to revoke another user's key by guessing an id.
     */
    public int revokeOwnedByUser(UUID id, UUID userId) {
        return jdbc.update(
                "UPDATE api_keys SET revoked_at = now() WHERE id = ? AND created_by_user_id = ? AND revoked_at IS NULL",
                id,
                userId);
    }

    public int revokeWithinOrganization(UUID id, UUID organizationId) {
        return jdbc.update(
                "UPDATE api_keys SET revoked_at = now() WHERE id = ? AND organization_id = ? AND revoked_at IS NULL",
                id,
                organizationId);
    }

    /**
     * A security review found disabling a user revoked their refresh tokens (so their next login
     * attempt/refresh fails) but left any API key they'd created fully working for up to its full
     * expiry (default 90 days) - {@link ApiKey#isActive} only ever checks revocation/expiry, never
     * the creating user's live status. Called from OrgUserController#update whenever a status
     * change lands on DISABLED, the same moment refresh tokens already get revoked.
     */
    public int revokeAllForUser(UUID userId) {
        return jdbc.update(
                "UPDATE api_keys SET revoked_at = now() WHERE created_by_user_id = ? AND revoked_at IS NULL", userId);
    }
}
