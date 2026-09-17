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
            rs.getTimestamp("created_at").toInstant(),
            rs.getString("notes"));

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

    /**
     * Active only - a soft-removed target (is_active = FALSE) drives no scanning traffic of its
     * own (see ScanAutoScheduler#findDueForScan), so it shouldn't count against the org's cap on
     * concurrent outbound scanning. An org can always make room for a new target by removing an
     * old one first, without needing to permanently delete anything.
     */
    public int countActiveByOrganization(UUID organizationId) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM targets WHERE organization_id = ? AND is_active = TRUE",
                Integer.class,
                organizationId);
        return count != null ? count : 0;
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

    /** A blank string clears the notes (stored as NULL, not empty-string) - "" and "no notes" should mean the same thing, not two distinct states a caller has to reason about. */
    public void updateNotes(UUID id, String notes) {
        jdbc.update("UPDATE targets SET notes = ? WHERE id = ?", notes == null || notes.isBlank() ? null : notes, id);
    }

    /**
     * A product review found targetType (OWN/COMPETITOR/WATCHLIST) was set once at creation and
     * never editable again - a target mis-picked as WATCHLIST when it was actually OWN (which
     * gates the "Deep scan" button and /compare's default OWN-vs-competitors framing) had no fix
     * short of the ADMIN-only, cascading hard delete (see TargetController#delete) and recreating
     * the target from scratch, losing its entire finding/subdomain/scan history. Purely a
     * categorization label - completely independent of {@code authorization_status}, the actual
     * security boundary Tier 2 active scanning checks (see
     * TargetAuthorizationController/TargetController#deepScanNow) - so relabeling a target OWN
     * here never grants deep-scan authorization by itself; that still requires its own separate
     * verification.
     */
    public void updateTargetType(UUID id, String targetType) {
        jdbc.update("UPDATE targets SET target_type = ? WHERE id = ?", targetType, id);
    }

    /** Member targets of a portfolio - see PortfolioService for the blended score computed over these. */
    public List<Target> findByPortfolio(UUID portfolioId) {
        return jdbc.query("SELECT * FROM targets WHERE portfolio_id = ? ORDER BY hostname ASC", ROW_MAPPER, portfolioId);
    }

    /**
     * Null removes this target from whatever portfolio it's currently in; a non-null value both
     * adds it to a portfolio and moves it out of any other it was already in (a plain overwrite
     * of the single portfolio_id FK - see V63__portfolios.sql for why a target belongs to at most
     * one portfolio).
     */
    public void updatePortfolio(UUID id, UUID portfolioId) {
        jdbc.update("UPDATE targets SET portfolio_id = ? WHERE id = ?", portfolioId, id);
    }

    /** Confirms targetId is currently a member of portfolioId - PortfolioController#removeMember uses this to 404 on "remove a target that isn't actually in this portfolio" rather than silently no-op. */
    public boolean isInPortfolio(UUID targetId, UUID portfolioId) {
        Boolean result = jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM targets WHERE id = ? AND portfolio_id = ?)",
                Boolean.class,
                targetId,
                portfolioId);
        return Boolean.TRUE.equals(result);
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

    /**
     * Lean, single-column fetch - never pulled as part of the regular Target row mapping, which
     * every other endpoint uses.
     *
     * <p>{@code Optional.ofNullable(...get(0))}, not {@code .stream().findFirst()}: the target
     * row legitimately exists with {@code homepage_screenshot_png} SQL-NULL for the common case
     * of "not screenshotted yet" (or never Tier-2 authorized) - a null-valued row makes {@code
     * List.stream().findFirst()} throw NullPointerException (it wraps the element via {@code
     * Optional.of}, not {@code ofNullable}), not return an empty/filtered Optional as the
     * previous code here assumed. Confirmed live: GET .../real-domain-screenshot 500'd instead
     * of 404ing for a real target with no screenshot yet.
     */
    public Optional<byte[]> findHomepageScreenshotPng(UUID id) {
        List<byte[]> rows =
                jdbc.query("SELECT homepage_screenshot_png FROM targets WHERE id = ?", (rs, rowNum) -> rs.getBytes(1), id);
        return rows.isEmpty() ? Optional.empty() : Optional.ofNullable(rows.get(0));
    }
}
