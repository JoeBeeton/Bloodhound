package org.freedonia.bloodhound.server.target;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Owns target_authorizations plus the derived targets.authorization_status
 * flag they gate. Re-authorizing an already-authorized target simply records
 * a fresh attestation row rather than erroring or silently replacing the
 * existing one - both represent genuine, independently-logged authorization
 * intervals, and revocation is a deliberate separate action (see {@link
 * #revokeCurrent}), not something a repeat authorize should imply.
 */
@Repository
public class TargetAuthorizationRepository {

    private static final RowMapper<TargetAuthorization> ROW_MAPPER = (rs, rowNum) -> new TargetAuthorization(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            UUID.fromString(rs.getString("authorized_by_user_id")),
            rs.getTimestamp("authorized_at").toInstant(),
            rs.getString("attestation_text"),
            rs.getTimestamp("revoked_at") != null ? rs.getTimestamp("revoked_at").toInstant() : null,
            rs.getString("revoked_by_user_id") != null ? UUID.fromString(rs.getString("revoked_by_user_id")) : null);

    private final JdbcTemplate jdbc;

    public TargetAuthorizationRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public TargetAuthorization authorize(UUID targetId, UUID authorizedByUserId, String attestationText) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO target_authorizations (id, target_id, authorized_by_user_id, attestation_text) "
                        + "VALUES (?, ?, ?, ?)",
                id,
                targetId,
                authorizedByUserId,
                attestationText);
        jdbc.update("UPDATE targets SET authorization_status = 'AUTHORIZED' WHERE id = ?", targetId);
        return findById(id).orElseThrow();
    }

    /** No-op (returns false) if there was no current authorization to revoke. */
    @Transactional
    public boolean revokeCurrent(UUID targetId, UUID revokedByUserId) {
        int updated = jdbc.update(
                "UPDATE target_authorizations SET revoked_at = now(), revoked_by_user_id = ? "
                        + "WHERE target_id = ? AND revoked_at IS NULL",
                revokedByUserId,
                targetId);
        jdbc.update("UPDATE targets SET authorization_status = 'UNAUTHORIZED' WHERE id = ?", targetId);
        return updated > 0;
    }

    public Optional<TargetAuthorization> findById(UUID id) {
        return jdbc.query("SELECT * FROM target_authorizations WHERE id = ?", ROW_MAPPER, id).stream()
                .findFirst();
    }

    /** The active (non-revoked) attestation, if any - there should be at most one at a time in practice. */
    public Optional<TargetAuthorization> findCurrent(UUID targetId) {
        return jdbc.query(
                        "SELECT * FROM target_authorizations WHERE target_id = ? AND revoked_at IS NULL "
                                + "ORDER BY authorized_at DESC LIMIT 1",
                        ROW_MAPPER,
                        targetId)
                .stream()
                .findFirst();
    }

    /** Full audit trail, current and revoked, newest first. */
    public List<TargetAuthorization> findHistory(UUID targetId) {
        return jdbc.query(
                "SELECT * FROM target_authorizations WHERE target_id = ? ORDER BY authorized_at DESC",
                ROW_MAPPER,
                targetId);
    }
}
