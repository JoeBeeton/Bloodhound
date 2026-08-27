package org.freedonia.bloodhound.server.findings;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Owns the findings table: the dedup-key lookup, insert/touch/resolve reconciliation writes, and query endpoints. */
@Repository
public class FindingRepository {

    private static final RowMapper<Finding> ROW_MAPPER = (rs, rowNum) -> new Finding(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("scan_run_id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getString("module_type"),
            rs.getString("rule_id"),
            rs.getString("severity"),
            rs.getString("category"),
            rs.getString("title"),
            rs.getString("description"),
            rs.getString("evidence"),
            rs.getString("affected_asset"),
            UUID.fromString(rs.getString("first_detected_scan_run_id")),
            rs.getString("status"),
            rs.getTimestamp("resolved_at") != null ? rs.getTimestamp("resolved_at").toInstant() : null,
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant());

    private static final RowMapper<OpenFindingKey> KEY_MAPPER = (rs, rowNum) -> new OpenFindingKey(
            UUID.fromString(rs.getString("id")), rs.getString("rule_id"), rs.getString("affected_asset"));

    /**
     * first_seen_at and remediation_advice aren't columns on `findings` itself - first_seen_at
     * is derived by joining first_detected_scan_run_id to scan_runs (falling back to started_at
     * when a run is still in progress and hasn't completed_at yet, which shouldn't happen for an
     * already-persisted finding but is a defensive fallback rather than a NULL), and
     * remediation_advice comes from rules_catalog keyed by rule_id - which has no row at all for
     * ZAP_ALERT_* findings (ZAP supplies its own remediation text directly into evidence.solution
     * at ingestion instead), hence the LEFT JOIN and the null-safe fallback in the DTO layer.
     */
    private static final RowMapper<FindingDetail> DETAIL_MAPPER = (rs, rowNum) -> new FindingDetail(
            ROW_MAPPER.mapRow(rs, rowNum),
            rs.getTimestamp("first_seen_at") != null ? rs.getTimestamp("first_seen_at").toInstant() : null,
            rs.getString("remediation_advice"));

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public FindingRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public List<OpenFindingKey> findOpenKeys(UUID targetId, String moduleType) {
        return jdbc.query(
                "SELECT id, rule_id, affected_asset FROM findings WHERE target_id = ? AND module_type = ? AND status = 'OPEN'",
                KEY_MAPPER,
                targetId,
                moduleType);
    }

    public void insert(UUID scanRunId, UUID targetId, String moduleType, FindingPayload payload) {
        jdbc.update(
                "INSERT INTO findings (id, scan_run_id, target_id, module_type, rule_id, severity, category, "
                        + "title, description, evidence, affected_asset, first_detected_scan_run_id) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)",
                UUID.randomUUID(),
                scanRunId,
                targetId,
                moduleType,
                payload.ruleId(),
                payload.severity(),
                payload.category(),
                payload.title(),
                payload.description(),
                writeJson(payload.evidence()),
                payload.affectedAsset(),
                scanRunId);
    }

    /** Reproduced again this run: bump updated_at and move scan_run_id to the current run, without duplicating the row. */
    public void touch(List<UUID> ids, UUID scanRunId) {
        for (UUID id : ids) {
            jdbc.update("UPDATE findings SET scan_run_id = ?, updated_at = now() WHERE id = ?", scanRunId, id);
        }
    }

    public void resolve(List<UUID> ids) {
        for (UUID id : ids) {
            jdbc.update("UPDATE findings SET status = 'RESOLVED', resolved_at = now(), updated_at = now() WHERE id = ?", id);
        }
    }

    private static final RowMapper<Finding> SCORING_ROW_MAPPER = (rs, rowNum) -> new Finding(
            UUID.fromString(rs.getString("id")),
            null,
            UUID.fromString(rs.getString("target_id")),
            null,
            rs.getString("rule_id"),
            rs.getString("severity"),
            rs.getString("category"),
            null,
            null,
            null,
            rs.getString("affected_asset"),
            null,
            "OPEN",
            null,
            null,
            null);

    /**
     * Lightweight projection for scoring/compound-risk context - carries only the fields
     * {@link org.freedonia.bloodhound.server.scoring.ScoringEngine}, {@link
     * org.freedonia.bloodhound.server.scoring.ScoreImpactCalculator}, and {@link
     * org.freedonia.bloodhound.server.compound.CompoundRiskEngine} actually read (id, target,
     * ruleId, severity, category, affectedAsset), not {@code SELECT *}. This context gets
     * fetched on essentially every dashboard/findings-list/score-snapshot computation for a
     * target - confirmed live that {@code SELECT *} here moved 16MB per request for one real
     * target with 36,466 open findings, almost entirely title/description/evidence text that
     * none of those three consumers ever look at (that data volume, not CPU, was the last
     * remaining chunk of an 8+ second response after the O(n log n) scoring rewrite and the
     * BigDecimal precision fix already resolved the CPU side). Every other {@link Finding}
     * field is null on rows this returns - never use it where those are needed.
     */
    public List<Finding> findOpenForScoring(UUID targetId) {
        return jdbc.query(
                "SELECT id, target_id, rule_id, severity, category, affected_asset FROM findings "
                        + "WHERE target_id = ? AND status = 'OPEN'",
                SCORING_ROW_MAPPER,
                targetId);
    }

    /** Defaults to status=OPEN when {@code status} is null - "current findings for a target" means open ones. */
    public List<Finding> findByTarget(UUID targetId, String severity, String category, String status) {
        StringBuilder sql = new StringBuilder("SELECT * FROM findings WHERE target_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(targetId);
        if (severity != null) {
            sql.append(" AND severity = ?");
            args.add(severity);
        }
        if (category != null) {
            sql.append(" AND category = ?");
            args.add(category);
        }
        sql.append(" AND status = ?");
        args.add(status != null ? status : "OPEN");
        sql.append(" ORDER BY CASE severity "
                + "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                + "created_at DESC");
        return jdbc.query(sql.toString(), ROW_MAPPER, args.toArray());
    }

    /**
     * Same as findByTarget, but also carries first_seen_at/remediation_advice for the
     * finding-detail view - kept as a separate method rather than widening findByTarget's
     * return type everywhere, since ScoreImpactCalculator/scoring only ever need the plain
     * Finding and don't care about display-only metadata.
     *
     * <p>severity/category accept a comma-separated list (multi-select filtering), matching
     * the pattern findOpenByOrganization already uses for severity - a bare single value
     * works too since a 1-element split is just that value.
     */
    /**
     * Bounded, offset-paginated - like {@code SubdomainRepository#findByTarget},
     * this backs a browser-facing endpoint and a target's open-finding count
     * is unbounded in principle (confirmed live: 36,466 for one target in
     * this deployment - that specific request took over two minutes and
     * never actually returned before this was added). See {@link
     * #countByTargetFiltered} for the total. Score-impact computation is
     * unaffected by this cap: it still needs, and still gets, the target's
     * FULL open set as context (see {@code FindingController#list}) - only
     * the rows actually shipped to the browser are limited here.
     */
    public List<FindingDetail> findByTargetDetailed(
            UUID targetId, String severity, String category, String status, String affectedAsset, int limit, int offset) {
        StringBuilder sql = new StringBuilder(
                "SELECT f.*, COALESCE(sr.completed_at, sr.started_at) AS first_seen_at, "
                        + "rc.remediation_advice AS remediation_advice "
                        + "FROM findings f "
                        + "LEFT JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                        + "LEFT JOIN rules_catalog rc ON rc.rule_id = f.rule_id "
                        + "WHERE f.target_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(targetId);
        appendFilters(sql, args, severity, category, status, affectedAsset);
        sql.append(" ORDER BY CASE f.severity "
                + "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                + "f.created_at DESC LIMIT ? OFFSET ?");
        args.add(limit);
        args.add(offset);
        return jdbc.query(sql.toString(), DETAIL_MAPPER, args.toArray());
    }

    /** Same filters as {@link #findByTargetDetailed}, unpaginated count - lets a caller show "showing N of TOTAL". */
    public int countByTargetFiltered(UUID targetId, String severity, String category, String status, String affectedAsset) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM findings f WHERE f.target_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(targetId);
        appendFilters(sql, args, severity, category, status, affectedAsset);
        Integer count = jdbc.queryForObject(sql.toString(), Integer.class, args.toArray());
        return count != null ? count : 0;
    }

    private static void appendFilters(
            StringBuilder sql, List<Object> args, String severity, String category, String status, String affectedAsset) {
        appendInClause(sql, args, "f.severity", severity);
        appendInClause(sql, args, "f.category", category);
        if (affectedAsset != null) {
            sql.append(" AND f.affected_asset = ?");
            args.add(affectedAsset);
        }
        sql.append(" AND f.status = ?");
        args.add(status != null ? status : "OPEN");
    }

    /** Appends " AND column IN (?,?,...)" for a comma-separated value list; a no-op if csv is null/blank. */
    private static void appendInClause(StringBuilder sql, List<Object> args, String column, String csv) {
        if (csv == null || csv.isBlank()) {
            return;
        }
        List<String> values = List.of(csv.split(","));
        sql.append(" AND ")
                .append(column)
                .append(" IN (")
                .append(String.join(",", values.stream().map(v -> "?").toList()))
                .append(")");
        args.addAll(values);
    }

    private static final RowMapper<OrgFinding> ORG_FINDING_MAPPER = (rs, rowNum) -> new OrgFinding(
            ROW_MAPPER.mapRow(rs, rowNum),
            rs.getString("target_hostname"),
            rs.getTimestamp("first_seen_at") != null ? rs.getTimestamp("first_seen_at").toInstant() : null,
            rs.getString("remediation_advice"));

    /** Org-wide findings for the dashboard's "top open findings" widget - joined with hostname since these span multiple targets. */
    public List<OrgFinding> findOpenByOrganization(UUID organizationId, List<String> severities, int limit) {
        StringBuilder sql = new StringBuilder(
                "SELECT f.*, t.hostname AS target_hostname, "
                        + "COALESCE(sr.completed_at, sr.started_at) AS first_seen_at, "
                        + "rc.remediation_advice AS remediation_advice "
                        + "FROM findings f "
                        + "JOIN targets t ON t.id = f.target_id "
                        + "LEFT JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                        + "LEFT JOIN rules_catalog rc ON rc.rule_id = f.rule_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = 'OPEN'");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        if (severities != null && !severities.isEmpty()) {
            sql.append(" AND f.severity IN (")
                    .append(String.join(",", severities.stream().map(s -> "?").toList()))
                    .append(")");
            args.addAll(severities);
        }
        sql.append(" ORDER BY CASE f.severity "
                + "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                + "f.created_at DESC LIMIT ?");
        args.add(limit);
        return jdbc.query(sql.toString(), ORG_FINDING_MAPPER, args.toArray());
    }

    /**
     * Org-wide findings for the dashboard's "recent findings" widget - purely chronological
     * (all severities, most recently discovered first), a deliberately different ordering from
     * {@link #findOpenByOrganization}'s severity-first one above: that widget answers "what's
     * most urgent right now", this one answers "what's new since I last looked", and a
     * low-severity finding discovered five minutes ago is exactly the kind of thing the
     * severity-ranked list would bury far down (or exclude outright, since that list is
     * CRITICAL/HIGH-only) but that's still worth surfacing here.
     */
    public List<OrgFinding> findRecentByOrganization(UUID organizationId, int limit) {
        String sql = "SELECT f.*, t.hostname AS target_hostname, "
                + "COALESCE(sr.completed_at, sr.started_at) AS first_seen_at, "
                + "rc.remediation_advice AS remediation_advice "
                + "FROM findings f "
                + "JOIN targets t ON t.id = f.target_id "
                + "LEFT JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                + "LEFT JOIN rules_catalog rc ON rc.rule_id = f.rule_id "
                + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = 'OPEN' "
                + "ORDER BY f.created_at DESC LIMIT ?";
        return jdbc.query(sql, ORG_FINDING_MAPPER, organizationId, limit);
    }

    /** Unbounded count backing the dashboard's stat tiles - findOpenByOrganization above is display-limited, this isn't. */
    public int countOpenByOrganization(UUID organizationId, List<String> severities) {
        StringBuilder sql = new StringBuilder(
                "SELECT COUNT(*) FROM findings f JOIN targets t ON t.id = f.target_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = 'OPEN'");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        if (severities != null && !severities.isEmpty()) {
            sql.append(" AND f.severity IN (")
                    .append(String.join(",", severities.stream().map(s -> "?").toList()))
                    .append(")");
            args.addAll(severities);
        }
        Integer count = jdbc.queryForObject(sql.toString(), Integer.class, args.toArray());
        return count != null ? count : 0;
    }

    /**
     * Point-in-time reconstruction: the findings that were OPEN as of a given
     * scan run's completion, reconstructed from the rolling {@code findings}
     * set via {@code first_detected_scan_run_id} and {@code resolved_at}
     * rather than a per-run snapshot table. Used by the diff endpoint to
     * compare two historical moments for the same target.
     */
    public List<Finding> findOpenAsOf(UUID targetId, Instant asOf) {
        Timestamp cutoff = Timestamp.from(asOf);
        return jdbc.query(
                "SELECT f.* FROM findings f "
                        + "JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                        + "WHERE f.target_id = ? AND sr.completed_at IS NOT NULL AND sr.completed_at <= ? "
                        + "AND (f.resolved_at IS NULL OR f.resolved_at > ?)",
                ROW_MAPPER,
                targetId,
                cutoff,
                cutoff);
    }

    /**
     * Findings first detected by this exact scan_run, at Medium+ severity - backs the
     * NEW_FINDINGS notification's batched count (see notification.NotificationService).
     * Low/Info is excluded here (not just styled differently) since that's the bulk of
     * real per-scan noise (e.g. SUBDOMAIN_NEW_UNEXPECTED fires at Info for every newly
     * discovered subdomain) - those stay fully visible in the findings list itself,
     * they just don't each count toward triggering a notification.
     */
    public int countNewSince(UUID scanRunId) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM findings WHERE first_detected_scan_run_id = ? "
                        + "AND severity IN ('CRITICAL','HIGH','MEDIUM')",
                Integer.class,
                scanRunId);
        return count != null ? count : 0;
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? java.util.Map.of() : value);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize finding evidence", e);
        }
    }
}
