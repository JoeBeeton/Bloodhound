package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Mirrors auth.WorkerCredentialRepository's hash-at-rest pattern, scoped to an organization per token. */
@Repository
public class ScimTokenRepository {

    private static final RowMapper<ScimToken> ROW_MAPPER = (rs, rowNum) -> new ScimToken(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("label"),
            rs.getString("token_hash"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("revoked_at") != null ? rs.getTimestamp("revoked_at").toInstant() : null);

    private final JdbcTemplate jdbc;

    public ScimTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ScimToken> findActiveByTokenHash(String tokenHash) {
        return jdbc.query("SELECT * FROM scim_tokens WHERE token_hash = ?", ROW_MAPPER, tokenHash).stream()
                .findFirst()
                .filter(t -> t.revokedAt() == null);
    }

    public List<ScimToken> findByOrganization(UUID organizationId) {
        return jdbc.query(
                "SELECT * FROM scim_tokens WHERE organization_id = ? ORDER BY created_at DESC",
                ROW_MAPPER,
                organizationId);
    }

    public ScimToken insert(UUID organizationId, String label, String tokenHash) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO scim_tokens (id, organization_id, label, token_hash) VALUES (?, ?, ?, ?)",
                id,
                organizationId,
                label,
                tokenHash);
        return jdbc.query("SELECT * FROM scim_tokens WHERE id = ?", ROW_MAPPER, id).get(0);
    }

    /** Revokes only if the token belongs to the given org - callers must not be able to revoke another org's token by guessing an id. */
    public int revoke(UUID id, UUID organizationId) {
        return jdbc.update(
                "UPDATE scim_tokens SET revoked_at = now() WHERE id = ? AND organization_id = ? AND revoked_at IS NULL",
                id,
                organizationId);
    }
}
