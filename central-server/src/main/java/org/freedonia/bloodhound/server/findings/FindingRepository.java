package org.freedonia.bloodhound.server.findings;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Owns the findings table: the dedup-key lookup, insert/touch/resolve reconciliation writes, and query endpoints. */
@Repository
public class FindingRepository {

    private static final RowMapper<Finding> ROW_MAPPER = (rs, rowNum) -> new Finding(
            UUID.fromString(rs.getString("id")),
            rs.getString("display_id"),
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
            rs.getTimestamp("updated_at").toInstant(),
            rs.getString("status_reason"));

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

    /**
     * The open findings a job's results are reconciled against. {@code scanScope} is the host a
     * per-host Tier 2 job was responsible for (see V53's migration comment for the flapping bug
     * this scoping fixes), or null for a whole-target module. A scoped lookup also picks up
     * NULL-scope rows of the same module: those are pre-V53 legacy findings the backfill couldn't
     * attribute to a host, and the alternative - never resolving them by anything - is worse than
     * one final flap that re-creates them under the right scope.
     */
    public List<OpenFindingKey> findOpenKeys(UUID targetId, String moduleType, String scanScope) {
        if (scanScope == null) {
            return jdbc.query(
                    "SELECT id, rule_id, affected_asset FROM findings WHERE target_id = ? AND module_type = ? "
                            + "AND status = 'OPEN' AND scan_scope IS NULL",
                    KEY_MAPPER,
                    targetId,
                    moduleType);
        }
        return jdbc.query(
                "SELECT id, rule_id, affected_asset FROM findings WHERE target_id = ? AND module_type = ? "
                        + "AND status = 'OPEN' AND (scan_scope = ? OR scan_scope IS NULL)",
                KEY_MAPPER,
                targetId,
                moduleType,
                scanScope);
    }

    public void insert(UUID scanRunId, UUID targetId, String moduleType, String scanScope, FindingPayload payload) {
        String displayId = nextDisplayId(targetId);
        jdbc.update(
                "INSERT INTO findings (id, display_id, scan_run_id, target_id, module_type, rule_id, severity, category, "
                        + "title, description, evidence, affected_asset, first_detected_scan_run_id, scan_scope) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?)",
                UUID.randomUUID(),
                displayId,
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
                scanRunId,
                scanScope);
    }

    /**
     * Atomically claims the next sequential number for this target and returns the full
     * "bh-&lt;hostname&gt;-&lt;n&gt;" display id. Safe under concurrent inserts for the same target
     * (multiple worker replicas reporting findings for the same host around the same time,
     * exactly the scenario that produced a real duplicate-finding bug elsewhere in this ingestion
     * path - see FindingReconciler): the UPDATE...RETURNING below is a single atomic SQL
     * statement, and Postgres serializes concurrent UPDATEs to the same targets row via
     * row-level locking, so two callers can never be handed the same number - unlike a
     * read-then-write "SELECT next_finding_number, then UPDATE" pattern, which would have
     * exactly the same race window as that bug.
     */
    private String nextDisplayId(UUID targetId) {
        java.util.Map<String, Object> row = jdbc.queryForMap(
                "UPDATE targets SET next_finding_number = next_finding_number + 1 WHERE id = ? "
                        + "RETURNING next_finding_number - 1 AS claimed_number, hostname",
                targetId);
        return "bh-" + row.get("hostname") + "-" + row.get("claimed_number");
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

    /** Used by FindingController's dismiss/reopen actions to look up the finding and verify its target before mutating - no other caller needs a single finding by id today. */
    public Optional<Finding> findById(UUID id) {
        return jdbc.query("SELECT * FROM findings WHERE id = ?", ROW_MAPPER, id).stream().findFirst();
    }

    /**
     * Only transitions from OPEN, not RESOLVED/ACCEPTED_RISK/already-DISMISSED - see
     * V48__findings_dismissed_status.sql's own comment for why DISMISSED is a sticky human
     * override on an otherwise-open finding specifically, not a general-purpose status field.
     * Returns the row count so the controller can tell "nothing happened because it wasn't OPEN"
     * apart from "the id doesn't exist" (already handled by the controller's own findById check
     * before this is ever called). {@code reason} (nullable - see V118's own comment) is the
     * analyst's free-text note for why, e.g. "false positive, third-party CDN".
     */
    public int dismiss(UUID id, String reason) {
        return jdbc.update(
                "UPDATE findings SET status = 'DISMISSED', status_reason = ?, updated_at = now() WHERE id = ? AND status = 'OPEN'",
                reason,
                id);
    }

    /**
     * The other sticky human override alongside {@link #dismiss} - same "only transitions from
     * OPEN, never reopened by FindingReconciler" treatment (findOpenKeys only ever sees
     * status='OPEN' rows), but for a finding that's real and acknowledged rather than a false
     * positive: the distinction a reviewer otherwise has no way to record other than losing it
     * in the same DISMISSED bucket as "this isn't actually an issue".
     */
    public int acceptRisk(UUID id, String reason) {
        return jdbc.update(
                "UPDATE findings SET status = 'ACCEPTED_RISK', status_reason = ?, updated_at = now() WHERE id = ? AND status = 'OPEN'",
                reason,
                id);
    }

    /**
     * The only way a DISMISSED or ACCEPTED_RISK finding ever leaves that state - see dismiss()'s
     * own comment. Only transitions back to OPEN (not RESOLVED - a dismissed/accepted-risk
     * finding was, by definition, still actually open when that status was set). Clears
     * status_reason: a reopened finding is active again, and the prior "why this was set aside"
     * note would be stale and misleading left in place.
     */
    public int reopen(UUID id) {
        return jdbc.update(
                "UPDATE findings SET status = 'OPEN', status_reason = NULL, updated_at = now() "
                        + "WHERE id = ? AND status IN ('DISMISSED', 'ACCEPTED_RISK')",
                id);
    }

    private static final RowMapper<Finding> SCORING_ROW_MAPPER = (rs, rowNum) -> new Finding(
            UUID.fromString(rs.getString("id")),
            null,
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
            UUID targetId,
            String severity,
            String category,
            String status,
            String affectedAsset,
            String search,
            int limit,
            int offset) {
        StringBuilder sql = new StringBuilder(
                "SELECT f.*, COALESCE(sr.completed_at, sr.started_at) AS first_seen_at, "
                        + "rc.remediation_advice AS remediation_advice "
                        + "FROM findings f "
                        + "LEFT JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                        + "LEFT JOIN rules_catalog rc ON rc.rule_id = f.rule_id "
                        + "WHERE f.target_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(targetId);
        appendFilters(sql, args, severity, category, status, affectedAsset, search);
        sql.append(" ORDER BY CASE f.severity "
                + "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                + "f.created_at DESC LIMIT ? OFFSET ?");
        args.add(limit);
        args.add(offset);
        return jdbc.query(sql.toString(), DETAIL_MAPPER, args.toArray());
    }

    /** Same filters as {@link #findByTargetDetailed}, unpaginated count - lets a caller show "showing N of TOTAL". */
    public int countByTargetFiltered(
            UUID targetId, String severity, String category, String status, String affectedAsset, String search) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM findings f WHERE f.target_id = ?");
        List<Object> args = new ArrayList<>();
        args.add(targetId);
        appendFilters(sql, args, severity, category, status, affectedAsset, search);
        Integer count = jdbc.queryForObject(sql.toString(), Integer.class, args.toArray());
        return count != null ? count : 0;
    }

    private static void appendFilters(
            StringBuilder sql,
            List<Object> args,
            String severity,
            String category,
            String status,
            String affectedAsset,
            String search) {
        appendInClause(sql, args, "f.severity", severity);
        appendInClause(sql, args, "f.category", category);
        if (affectedAsset != null) {
            sql.append(" AND f.affected_asset = ?");
            args.add(affectedAsset);
        }
        appendSearchClause(sql, args, search);
        sql.append(" AND f.status = ?");
        args.add(status != null ? status : "OPEN");
    }

    /**
     * A product review found the only way to narrow findings was severity/category/status chips
     * and (target-scoped) an exact affected-asset match - there was no way to answer "which
     * findings mention X" (a CVE id, a header name, a hostname fragment) without paging through
     * everything by eye. Case-insensitive substring match against title OR description, same
     * ILIKE pattern already used for the audit log's actor-email filter - title is normally short
     * and specific (e.g. "Missing Content-Security-Policy header"), description often carries the
     * detail (e.g. a CVE id or affected package name) that title doesn't, so searching only one
     * would miss real matches a person typing a keyword would expect to find.
     */
    private static void appendSearchClause(StringBuilder sql, List<Object> args, String search) {
        if (search == null || search.isBlank()) {
            return;
        }
        sql.append(" AND (f.title ILIKE ? OR f.description ILIKE ?)");
        String needle = "%" + search + "%";
        args.add(needle);
        args.add(needle);
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
        return findOpenByOrganization(organizationId, severities, List.of(), "OPEN", null, null, limit, 0);
    }

    /**
     * Same as the 3-arg overload, plus category/status filtering and offset pagination - backs
     * the org-wide Findings page (a full, filterable, paginated browse of every finding across
     * every target - previously only viewable one target at a time, or capped to the dashboard's
     * top 10, and with no way to see resolved findings at all anywhere in the app). Kept as a
     * separate overload rather than changing the original's signature, so the dashboard/MCP call
     * sites (which only ever want an unpaginated OPEN-only top-N slice) don't need to pass params
     * they don't use. status defaults to OPEN when null/blank, same convention as {@link
     * #findByTargetDetailed} already uses for the identical "what does the caller mean by
     * omitting this" question.
     *
     * <p>targetId narrows this org-wide list down to one target - a product gap found live: the
     * Findings page had no way to look at just one target's findings without leaving it for the
     * per-target view, even though every other filter (severity/category/status/search) already
     * worked across the whole org. Null/absent behaves exactly as before (every target in the org).
     */
    public List<OrgFinding> findOpenByOrganization(
            UUID organizationId,
            List<String> severities,
            List<String> categories,
            String status,
            String search,
            UUID targetId,
            int limit,
            int offset) {
        StringBuilder sql = new StringBuilder(
                "SELECT f.*, t.hostname AS target_hostname, "
                        + "COALESCE(sr.completed_at, sr.started_at) AS first_seen_at, "
                        + "rc.remediation_advice AS remediation_advice "
                        + "FROM findings f "
                        + "JOIN targets t ON t.id = f.target_id "
                        + "LEFT JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                        + "LEFT JOIN rules_catalog rc ON rc.rule_id = f.rule_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = ?");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        args.add(status != null && !status.isBlank() ? status : "OPEN");
        appendInClause(sql, args, "f.severity", severities == null || severities.isEmpty() ? null : String.join(",", severities));
        appendInClause(sql, args, "f.category", categories == null || categories.isEmpty() ? null : String.join(",", categories));
        if (targetId != null) {
            sql.append(" AND f.target_id = ?");
            args.add(targetId);
        }
        appendSearchClause(sql, args, search);
        sql.append(" ORDER BY CASE f.severity "
                + "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                + "f.created_at DESC LIMIT ? OFFSET ?");
        args.add(limit);
        args.add(offset);
        return jdbc.query(sql.toString(), ORG_FINDING_MAPPER, args.toArray());
    }

    /** Unpaginated total matching {@link #findOpenByOrganization}'s filters - lets a caller show "showing N of TOTAL". */
    public int countOpenByOrganizationFiltered(
            UUID organizationId, List<String> severities, List<String> categories, String status, String search, UUID targetId) {
        StringBuilder sql = new StringBuilder(
                "SELECT COUNT(*) FROM findings f JOIN targets t ON t.id = f.target_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = ?");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        args.add(status != null && !status.isBlank() ? status : "OPEN");
        appendInClause(sql, args, "f.severity", severities == null || severities.isEmpty() ? null : String.join(",", severities));
        appendInClause(sql, args, "f.category", categories == null || categories.isEmpty() ? null : String.join(",", categories));
        if (targetId != null) {
            sql.append(" AND f.target_id = ?");
            args.add(targetId);
        }
        appendSearchClause(sql, args, search);
        Integer count = jdbc.queryForObject(sql.toString(), Integer.class, args.toArray());
        return count != null ? count : 0;
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
        return findRecentByOrganization(organizationId, List.of(), List.of(), null, null, null, null, limit, 0);
    }

    /**
     * Filterable, paginated version of the 2-arg overload above - backs the dedicated Findings
     * Feed page (a product/UX review found the dashboard's fixed top-10 "recent findings" widget
     * was the only chronological view anywhere in the app, with no way to page further back or
     * narrow by severity/category/status/search/target/day the way the org-wide /findings page
     * already could, plus a day-drill-down its own activity histogram needs). Ordered by
     * updated_at ("last seen" - see the findings table's own doc comment: it's bumped every time
     * a reproduced finding is touched, not just at creation), not created_at - a live report
     * caught this ordering by created_at instead, which made a finding that keeps getting
     * reconfirmed scan after scan drop out of a "what's happening right now" feed forever after
     * its first appearance, while looking like a severity-based sort whenever one module (e.g.
     * CVE correlation) happens to run last in every scan and so always produces the newest rows.
     * status defaults to OPEN when null/blank, same convention {@link #findOpenByOrganization}
     * already uses. {@code day} (nullable) narrows to findings created on that one calendar day -
     * the activity histogram's click-to-filter, which counts by created_at (see
     * {@link #findDailyActivity}), so this filters on the same column for consistency with it.
     */
    public List<OrgFinding> findRecentByOrganization(
            UUID organizationId,
            List<String> severities,
            List<String> categories,
            String status,
            String search,
            UUID targetId,
            LocalDate day,
            int limit,
            int offset) {
        StringBuilder sql = new StringBuilder(
                "SELECT f.*, t.hostname AS target_hostname, "
                        + "COALESCE(sr.completed_at, sr.started_at) AS first_seen_at, "
                        + "rc.remediation_advice AS remediation_advice "
                        + "FROM findings f "
                        + "JOIN targets t ON t.id = f.target_id "
                        + "LEFT JOIN scan_runs sr ON sr.id = f.first_detected_scan_run_id "
                        + "LEFT JOIN rules_catalog rc ON rc.rule_id = f.rule_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = ?");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        args.add(status != null && !status.isBlank() ? status : "OPEN");
        appendInClause(sql, args, "f.severity", severities == null || severities.isEmpty() ? null : String.join(",", severities));
        appendInClause(sql, args, "f.category", categories == null || categories.isEmpty() ? null : String.join(",", categories));
        if (targetId != null) {
            sql.append(" AND f.target_id = ?");
            args.add(targetId);
        }
        if (day != null) {
            sql.append(" AND f.created_at::date = ?");
            args.add(day);
        }
        appendSearchClause(sql, args, search);
        sql.append(" ORDER BY f.updated_at DESC LIMIT ? OFFSET ?");
        args.add(limit);
        args.add(offset);
        return jdbc.query(sql.toString(), ORG_FINDING_MAPPER, args.toArray());
    }

    /** Unpaginated total matching {@link #findRecentByOrganization}'s filters - lets the Findings Feed page show "showing N of TOTAL". */
    public int countRecentByOrganization(
            UUID organizationId,
            List<String> severities,
            List<String> categories,
            String status,
            String search,
            UUID targetId,
            LocalDate day) {
        StringBuilder sql = new StringBuilder(
                "SELECT COUNT(*) FROM findings f JOIN targets t ON t.id = f.target_id "
                        + "WHERE t.organization_id = ? AND t.is_active = true AND f.status = ?");
        List<Object> args = new ArrayList<>();
        args.add(organizationId);
        args.add(status != null && !status.isBlank() ? status : "OPEN");
        appendInClause(sql, args, "f.severity", severities == null || severities.isEmpty() ? null : String.join(",", severities));
        appendInClause(sql, args, "f.category", categories == null || categories.isEmpty() ? null : String.join(",", categories));
        if (targetId != null) {
            sql.append(" AND f.target_id = ?");
            args.add(targetId);
        }
        if (day != null) {
            sql.append(" AND f.created_at::date = ?");
            args.add(day);
        }
        appendSearchClause(sql, args, search);
        Integer count = jdbc.queryForObject(sql.toString(), Integer.class, args.toArray());
        return count != null ? count : 0;
    }

    public record FindingActivityBucket(LocalDate day, int critical, int high, int medium, int low, int info) {}

    /**
     * Daily finding-creation counts per severity for the last {@code days} days (including
     * today) - backs the Findings Feed page's activity histogram ("when did things spike"), not
     * "what's open now": deliberately counts every finding created in the window regardless of
     * its current status, since a since-resolved finding was still real activity on the day it
     * was first detected. Zero-filled in Java (not SQL) for every day and every severity in the
     * window, including days/severities with no rows at all, so the chart never has to guess
     * whether an absent key means zero or "we didn't ask."
     */
    public List<FindingActivityBucket> findDailyActivity(UUID organizationId, int days) {
        String sql = "SELECT date_trunc('day', f.created_at)::date AS day, f.severity, COUNT(*) AS cnt "
                + "FROM findings f JOIN targets t ON t.id = f.target_id "
                + "WHERE t.organization_id = ? AND f.created_at >= now() - (? || ' days')::interval "
                + "GROUP BY day, f.severity";
        Map<LocalDate, Map<String, Integer>> bySeverity = new HashMap<>();
        jdbc.query(sql, rs -> {
            LocalDate day = rs.getDate("day").toLocalDate();
            bySeverity.computeIfAbsent(day, d -> new HashMap<>()).put(rs.getString("severity"), rs.getInt("cnt"));
        }, organizationId, days);

        List<FindingActivityBucket> buckets = new ArrayList<>();
        LocalDate start = LocalDate.now().minusDays(days - 1L);
        for (int i = 0; i < days; i++) {
            LocalDate day = start.plusDays(i);
            Map<String, Integer> counts = bySeverity.getOrDefault(day, Map.of());
            buckets.add(new FindingActivityBucket(
                    day,
                    counts.getOrDefault("CRITICAL", 0),
                    counts.getOrDefault("HIGH", 0),
                    counts.getOrDefault("MEDIUM", 0),
                    counts.getOrDefault("LOW", 0),
                    counts.getOrDefault("INFO", 0)));
        }
        return buckets;
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

    /** {@code vendor} is the WAF product nuclei's waf-detect template identified (e.g. "cloudflare"), or null if
     * either no WAF was detected or this host hasn't been scanned by nuclei at all - {@code scanned}
     * disambiguates those two, see {@link #findWafStatusByTarget}. */
    public record WafStatus(String vendor, boolean scanned) {}

    /**
     * One {@link WafStatus} per hostname nuclei has scanned for this target (root apex and/or
     * subdomains - both flow through the same per-host {@code scan_scope}, see V53's migration).
     * {@code scanned=true} comes from the presence of ANY open {@code NUCLEI_*} finding for that
     * host - nuclei's template corpus is large enough (10,000+ templates) that a real, reachable
     * web host essentially always trips at least one INFO-level template (tech-detect,
     * missing-security-headers, etc.), so "at least one nuclei finding exists" is a reliable proxy
     * for "nuclei successfully scanned this host", without needing to separately plumb through
     * scan_jobs/last_scanned_at just for this. The one real edge case - a host nuclei scanned but
     * that happened to trip literally nothing - reads as "not yet scanned" instead of "scanned,
     * clean"; accepted as a good-enough approximation, same tradeoff this codebase already makes
     * for several other "no direct signal, use a strong correlate instead" cases (see
     * WHOIS_REGISTRANT_CHANGED's privacy-redaction note, for one). {@code vendor} comes
     * specifically from {@code NUCLEI_waf-detect}'s {@code matcherName} evidence key - see
     * NucleiFindingMapper's own comment for why that key (not something waf-detect-specific) is
     * where the vendor name lives.
     */
    public Map<String, WafStatus> findWafStatusByTarget(UUID targetId) {
        Map<String, String> vendorByHost = new HashMap<>();
        Set<String> scannedHosts = new HashSet<>();
        jdbc.query(
                "SELECT scan_scope, rule_id, evidence->>'matcherName' AS vendor FROM findings "
                        + "WHERE target_id = ? AND status = 'OPEN' AND rule_id LIKE 'NUCLEI_%' AND scan_scope IS NOT NULL",
                rs -> {
                    String host = rs.getString("scan_scope");
                    scannedHosts.add(host);
                    if ("NUCLEI_waf-detect".equals(rs.getString("rule_id"))) {
                        String vendor = rs.getString("vendor");
                        if (vendor != null && !vendor.isBlank()) {
                            vendorByHost.put(host, vendor);
                        }
                    }
                },
                targetId);
        Map<String, WafStatus> result = new HashMap<>();
        for (String host : scannedHosts) {
            result.put(host, new WafStatus(vendorByHost.get(host), true));
        }
        return result;
    }

    /** One row per open TLS-category finding for a hostname - the input to TlsGradeCalculator. Only the evidence keys the calculator actually needs are pulled out via ->> (same precedent as findWafStatusByTarget's own matcherName extraction) rather than deserializing the whole evidence blob. */
    public record TlsFindingRow(String ruleId, String title, String protocol, String cipherSuite) {}

    /**
     * Every open TLS finding for this target, grouped by hostname - see TlsGradeCalculator for how
     * these become a letter grade. Grouped by {@code affected_asset}, not {@code scan_scope}: unlike
     * NUCLEI (a per-host Tier 2 job, see findWafStatusByTarget), TLS_ANALYSIS is a Tier 1 module
     * that fans out across subdomains internally within one whole-target job, so scan_scope is
     * always null for its findings - confirmed live (every TLS_1_3_NOT_SUPPORTED row for a real
     * target had scan_scope NULL despite a correctly host-specific affected_asset). affected_asset
     * is the one field that's always the real per-host hostname - exactly (most rules) or as
     * "hostname: protocol" (TLS_WEAK_PROTOCOL_SUPPORTED's own convention, see TlsDecisionLogic#legacyProtocol) -
     * so the host is extracted by splitting on the first ": " when present.
     */
    public Map<String, List<TlsFindingRow>> findTlsFindingsByTarget(UUID targetId) {
        Map<String, List<TlsFindingRow>> result = new HashMap<>();
        jdbc.query(
                "SELECT affected_asset, rule_id, title, evidence->>'protocol' AS protocol, "
                        + "evidence->>'cipherSuite' AS cipher_suite FROM findings "
                        + "WHERE target_id = ? AND status = 'OPEN' AND category = 'TLS'",
                rs -> {
                    String host = hostFromAffectedAsset(rs.getString("affected_asset"));
                    result.computeIfAbsent(host, k -> new ArrayList<>())
                            .add(new TlsFindingRow(
                                    rs.getString("rule_id"),
                                    rs.getString("title"),
                                    rs.getString("protocol"),
                                    rs.getString("cipher_suite")));
                },
                targetId);
        return result;
    }

    private static String hostFromAffectedAsset(String affectedAsset) {
        int separator = affectedAsset.indexOf(": ");
        return separator < 0 ? affectedAsset : affectedAsset.substring(0, separator);
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? java.util.Map.of() : value);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize finding evidence", e);
        }
    }
}
