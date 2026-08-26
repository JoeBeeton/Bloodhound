package org.freedonia.bloodhound.server.notification;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class NotificationRepository {

    private static final RowMapper<Notification> ROW_MAPPER = (rs, rowNum) -> new Notification(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("type"),
            rs.getString("severity"),
            rs.getString("title"),
            rs.getString("message"),
            rs.getString("target_id") != null ? UUID.fromString(rs.getString("target_id")) : null,
            rs.getString("target_hostname"),
            rs.getString("scan_run_id") != null ? UUID.fromString(rs.getString("scan_run_id")) : null,
            rs.getBoolean("is_read"),
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public NotificationRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Notification insert(
            UUID organizationId,
            String type,
            String severity,
            String title,
            String message,
            UUID targetId,
            UUID scanRunId) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO notifications (id, organization_id, type, severity, title, message, target_id, scan_run_id) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                id,
                organizationId,
                type,
                severity,
                title,
                message,
                targetId,
                scanRunId);
        return findById(id);
    }

    private Notification findById(UUID id) {
        return jdbc.queryForObject(
                "SELECT n.*, t.hostname AS target_hostname FROM notifications n "
                        + "LEFT JOIN targets t ON t.id = n.target_id WHERE n.id = ?",
                ROW_MAPPER,
                id);
    }

    public List<Notification> findByOrganization(UUID organizationId, boolean unreadOnly, int limit) {
        String sql = "SELECT n.*, t.hostname AS target_hostname FROM notifications n "
                + "LEFT JOIN targets t ON t.id = n.target_id "
                + "WHERE n.organization_id = ?"
                + (unreadOnly ? " AND n.is_read = false" : "")
                + " ORDER BY n.created_at DESC LIMIT ?";
        return jdbc.query(sql, ROW_MAPPER, organizationId, limit);
    }

    public int countUnread(UUID organizationId) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM notifications WHERE organization_id = ? AND is_read = false",
                Integer.class,
                organizationId);
        return count != null ? count : 0;
    }

    /** Scoped by organization_id too, not just id - a notification id alone must never let one org mark another's as read. */
    public void markRead(UUID organizationId, UUID id) {
        jdbc.update(
                "UPDATE notifications SET is_read = true WHERE id = ? AND organization_id = ?", id, organizationId);
    }

    public void markAllRead(UUID organizationId) {
        jdbc.update(
                "UPDATE notifications SET is_read = true WHERE organization_id = ? AND is_read = false",
                organizationId);
    }
}
