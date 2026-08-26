package org.freedonia.bloodhound.server.jobqueue;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class ScanRunRepository {

    private static final RowMapper<ScanRun> ROW_MAPPER = (rs, rowNum) -> new ScanRun(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getString("triggered_by"),
            rs.getString("triggered_by_user_id") != null ? UUID.fromString(rs.getString("triggered_by_user_id")) : null,
            rs.getTimestamp("started_at").toInstant(),
            rs.getTimestamp("completed_at") != null ? rs.getTimestamp("completed_at").toInstant() : null,
            rs.getString("status"));

    private final JdbcTemplate jdbc;

    public ScanRunRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ScanRun> findById(UUID id) {
        return jdbc.query("SELECT * FROM scan_runs WHERE id = ?", ROW_MAPPER, id).stream()
                .findFirst();
    }

    public ScanRun insert(UUID targetId, String triggeredBy, UUID triggeredByUserId) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO scan_runs (id, target_id, triggered_by, triggered_by_user_id) VALUES (?, ?, ?, ?)",
                id,
                targetId,
                triggeredBy,
                triggeredByUserId);
        return findById(id).orElseThrow();
    }

    /**
     * No-op if the run isn't currently RUNNING (e.g. a duplicate completion
     * signal from two jobs finishing concurrently) - completion is applied
     * exactly once. Returns whether *this* call was the one that applied it,
     * so callers (scoring) can tell "I completed it" from "someone already
     * did" without a separate read-then-write race.
     */
    /** The scan run immediately prior to a given completion timestamp, for the same target - the "?against=previous" case of the findings diff. */
    public Optional<ScanRun> findPreviousCompleted(UUID targetId, Instant beforeCompletedAt) {
        return jdbc.query(
                        "SELECT * FROM scan_runs WHERE target_id = ? AND completed_at IS NOT NULL AND completed_at < ? "
                                + "ORDER BY completed_at DESC LIMIT 1",
                        ROW_MAPPER,
                        targetId,
                        Timestamp.from(beforeCompletedAt))
                .stream()
                .findFirst();
    }

    private static final RowMapper<OrgScanRun> ORG_RUN_MAPPER =
            (rs, rowNum) -> new OrgScanRun(ROW_MAPPER.mapRow(rs, rowNum), rs.getString("target_hostname"));

    /** Org-wide, cross-target recent scan activity - backs the dashboard's "recent activity" feed. */
    public java.util.List<OrgScanRun> findRecentByOrganization(UUID organizationId, int limit) {
        return jdbc.query(
                "SELECT sr.*, t.hostname AS target_hostname FROM scan_runs sr "
                        + "JOIN targets t ON t.id = sr.target_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true ORDER BY sr.started_at DESC LIMIT ?",
                ORG_RUN_MAPPER,
                organizationId,
                limit);
    }

    /** Every currently-RUNNING scan_run for the org's active targets - backs the /scans/active page. */
    public java.util.List<OrgScanRun> findRunningByOrganization(UUID organizationId) {
        return jdbc.query(
                "SELECT sr.*, t.hostname AS target_hostname FROM scan_runs sr "
                        + "JOIN targets t ON t.id = sr.target_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND sr.status = 'RUNNING' "
                        + "ORDER BY sr.started_at ASC",
                ORG_RUN_MAPPER,
                organizationId);
    }

    /**
     * Used by {@link ScanAutoScheduler} to avoid enqueuing a second Tier 1
     * scan for a target whose previous cycle is still going. Deliberately
     * excludes CT_CHECK runs: CtMonitorScheduler's lightweight crt.sh-diff
     * sweeps (every 20 min, plus one immediately on every startup) are their
     * own single-job run, independent of - and not in conflict with - a full
     * scan. Found via real testing: without this exclusion, a CT_CHECK that
     * happened to be in flight (e.g. crt.sh being slow, a known recurring
     * flakiness throughout this project) would wrongly block the actual
     * scheduled scan it has nothing to do with.
     */
    public boolean existsRunningForTarget(UUID targetId) {
        Boolean exists = jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM scan_runs WHERE target_id = ? AND status = 'RUNNING' AND triggered_by != 'CT_CHECK')",
                Boolean.class,
                targetId);
        return Boolean.TRUE.equals(exists);
    }

    public boolean markComplete(UUID id, String status) {
        int rows = jdbc.update(
                "UPDATE scan_runs SET status = ?, completed_at = now() WHERE id = ? AND status = 'RUNNING'",
                status,
                id);
        return rows > 0;
    }
}
