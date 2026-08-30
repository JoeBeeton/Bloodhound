package org.freedonia.bloodhound.server.audit;

import java.util.ArrayList;
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

    /**
     * actorEmail is a case-insensitive substring match ("who did this" is usually answered by
     * typing part of a name/email, not knowing the exact address); action is an exact match
     * against one of the fixed action strings AuditLogController's record() calls use - a
     * product review found the audit log had no way to filter at all, only chronological
     * paging, making "what did this admin do" or "show me every password reset" impractical
     * once there's more than a screenful of history.
     */
    public List<AuditLogEntry> findByOrganization(
            UUID organizationId, String actorEmail, String action, int limit, int offset) {
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_log WHERE organization_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        if (actorEmail != null && !actorEmail.isBlank()) {
            sql.append(" AND actor_email ILIKE ?");
            args.add("%" + actorEmail + "%");
        }
        if (action != null && !action.isBlank()) {
            sql.append(" AND action = ?");
            args.add(action);
        }
        sql.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
        args.add(limit);
        args.add(offset);
        return jdbc.query(sql.toString(), ROW_MAPPER, args.toArray());
    }

    /** Same filters as {@link #findByOrganization}, unpaginated count - lets a caller show "showing N of TOTAL". */
    public int countByOrganization(UUID organizationId, String actorEmail, String action) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM audit_log WHERE organization_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        if (actorEmail != null && !actorEmail.isBlank()) {
            sql.append(" AND actor_email ILIKE ?");
            args.add("%" + actorEmail + "%");
        }
        if (action != null && !action.isBlank()) {
            sql.append(" AND action = ?");
            args.add(action);
        }
        Integer count = jdbc.queryForObject(sql.toString(), Integer.class, args.toArray());
        return count != null ? count : 0;
    }
}
