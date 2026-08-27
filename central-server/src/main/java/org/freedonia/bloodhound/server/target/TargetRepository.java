package org.freedonia.bloodhound.server.target;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class TargetRepository {

    private static final RowMapper<Target> ROW_MAPPER = (rs, rowNum) -> new Target(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("hostname"),
            rs.getString("target_type"),
            rs.getString("authorization_status"),
            rs.getInt("scan_cadence_seconds"),
            rs.getTimestamp("next_scan_at").toInstant(),
            rs.getBoolean("is_active"),
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public TargetRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * @param includeInactive false (the default everywhere except the "show removed" list view)
     *     excludes soft-removed (is_active = FALSE) targets - see {@link #updateCadenceAndActive}.
     */
    public List<Target> findByOrganization(UUID organizationId, String targetType, boolean includeInactive) {
        String activeClause = includeInactive ? "" : " AND is_active = TRUE";
        if (targetType == null) {
            return jdbc.query(
                    "SELECT * FROM targets WHERE organization_id = ?" + activeClause + " ORDER BY created_at DESC",
                    ROW_MAPPER,
                    organizationId);
        }
        return jdbc.query(
                "SELECT * FROM targets WHERE organization_id = ? AND target_type = ?" + activeClause
                        + " ORDER BY created_at DESC",
                ROW_MAPPER,
                organizationId,
                targetType);
    }

    /** Active targets whose schedule has come due - used only by {@link org.freedonia.bloodhound.server.jobqueue.ScanAutoScheduler}. */
    public List<Target> findDueForScan() {
        return jdbc.query("SELECT * FROM targets WHERE is_active = TRUE AND next_scan_at <= now()", ROW_MAPPER);
    }

    public Optional<Target> findById(UUID id) {
        return jdbc.query("SELECT * FROM targets WHERE id = ?", ROW_MAPPER, id).stream()
                .findFirst();
    }

    /** Scoped lookup used by every endpoint that touches a single target - a mismatch reads as "not found", not "forbidden". */
    public Optional<Target> findByIdAndOrganization(UUID id, UUID organizationId) {
        return findById(id).filter(t -> t.organizationId().equals(organizationId));
    }

    /** Cross-organization - used only by CtMonitorScheduler's background sweep, never exposed via a user-facing endpoint. */
    public List<Target> findAllActive() {
        return jdbc.query("SELECT * FROM targets WHERE is_active = TRUE", ROW_MAPPER);
    }

    public Target insert(UUID organizationId, String hostname, String targetType) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO targets (id, organization_id, hostname, target_type, next_scan_at) "
                        + "VALUES (?, ?, ?, ?, now())",
                id,
                organizationId,
                hostname,
                targetType);
        return findById(id).orElseThrow();
    }

    public void updateCadenceAndActive(UUID id, Integer scanCadenceSeconds, Boolean isActive) {
        Target current = findById(id).orElseThrow();
        int cadence = scanCadenceSeconds != null ? scanCadenceSeconds : current.scanCadenceSeconds();
        boolean active = isActive != null ? isActive : current.isActive();
        jdbc.update("UPDATE targets SET scan_cadence_seconds = ?, is_active = ? WHERE id = ?", cadence, active, id);
    }

    public void delete(UUID id) {
        jdbc.update("DELETE FROM targets WHERE id = ?", id);
    }

    public void touchNextScanAt(UUID id, Instant nextScanAt) {
        jdbc.update("UPDATE targets SET next_scan_at = ? WHERE id = ?", Timestamp.from(nextScanAt), id);
    }

    /** Overwrites the previous screenshot (current-state, not history) - see TyposquatIngestionService. */
    public void updateHomepageScreenshot(UUID id, byte[] png) {
        jdbc.update("UPDATE targets SET homepage_screenshot_png = ? WHERE id = ?", png, id);
    }

    public boolean hasHomepageScreenshot(UUID id) {
        Boolean has = jdbc.queryForObject(
                "SELECT homepage_screenshot_png IS NOT NULL FROM targets WHERE id = ?", Boolean.class, id);
        return Boolean.TRUE.equals(has);
    }

    /** Lean, single-column fetch - never pulled as part of the regular Target row mapping, which every other endpoint uses. */
    public Optional<byte[]> findHomepageScreenshotPng(UUID id) {
        return jdbc.query("SELECT homepage_screenshot_png FROM targets WHERE id = ?", (rs, rowNum) -> rs.getBytes(1), id)
                .stream()
                .findFirst()
                .filter(bytes -> bytes != null);
    }
}
