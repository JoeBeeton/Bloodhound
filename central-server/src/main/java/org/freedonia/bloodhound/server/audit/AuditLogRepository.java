package org.freedonia.bloodhound.server.audit;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** See V43__audit_log.sql for why actor identity is snapshotted rather than joined live, and why target_id carries no FK. */
@Repository
public class AuditLogRepository {

    private static final RowMapper<AuditLogEntry> ROW_MAPPER = (rs, rowNum) -> new AuditLogEntry(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("actor_user_id") != null ? UUID.fromString(rs.getString("actor_user_id")) : null,
            rs.getString("actor_email"),
            rs.getString("action"),
            rs.getString("target_type"),
            rs.getString("target_id"),
            rs.getString("detail"),
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public AuditLogRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void record(
            UUID organizationId,
            UUID actorUserId,
            String actorEmail,
            String action,
            String targetType,
            String targetId,
            String detail) {
        jdbc.update(
                "INSERT INTO audit_log (id, organization_id, actor_user_id, actor_email, action, target_type, target_id, detail) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                UUID.randomUUID(),
                organizationId,
                actorUserId,
                actorEmail,
                action,
                targetType,
                targetId,
                detail);
    }

    public List<AuditLogEntry> findByOrganization(UUID organizationId, int limit, int offset) {
        return jdbc.query(
                "SELECT * FROM audit_log WHERE organization_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                ROW_MAPPER,
                organizationId,
                limit,
                offset);
    }

    public int countByOrganization(UUID organizationId) {
        Integer count =
                jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE organization_id = ?", Integer.class, organizationId);
        return count != null ? count : 0;
    }
}
