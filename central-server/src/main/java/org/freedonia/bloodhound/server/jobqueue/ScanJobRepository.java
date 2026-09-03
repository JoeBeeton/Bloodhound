package org.freedonia.bloodhound.server.jobqueue;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Owns the scan_jobs queue table, in particular the claim query - the one
 * piece of this whole system where getting the SQL exactly right matters
 * most. See {@link #claim} for the FOR UPDATE SKIP LOCKED mechanics.
 */
@Repository
public class ScanJobRepository {

    /**
     * Unlike every other Tier 2 module, ZAP_ACTIVE_SCAN drives a single shared {@code zap}
     * sidecar container (not scaled per worker replica - see docker-compose.yml), and OWASP ZAP
     * itself is CPU/thread-heavy per concurrent spider+active-scan session. Confirmed live: with
     * 4 worker replicas each independently running their own ZAP_ACTIVE_SCAN job, the zap
     * container pegged at 100%+ CPU and stopped answering even trivial status-check API calls
     * within their 30s timeout, failing every in-flight scan with "failed to reach ZAP". The job
     * queue has no other concept of "this module type shares an external bottleneck" - {@link
     * #claim} caps how many ZAP_ACTIVE_SCAN jobs can be CLAIMED/RUNNING at once, independent of
     * how many workers exist, so scaling workers up for every other module type doesn't also
     * scale up load against the one shared ZAP instance. A small approximate-not-exact race is
     * possible (two concurrent claim() calls could both see the cap not yet reached and each
     * claim one, momentarily exceeding it by one) - acceptable, same tolerance for benign
     * raciness FOR UPDATE SKIP LOCKED already accepts elsewhere in this query.
     */
    @Value("${bloodhound.zap.max-concurrent-scans:1}")
    private int zapMaxConcurrentScans = 1;

    private static final RowMapper<ScanJob> ROW_MAPPER = (rs, rowNum) -> new ScanJob(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("scan_run_id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getString("module_type"),
            rs.getString("status"),
            rs.getShort("priority"),
            rs.getTimestamp("run_after").toInstant(),
            rs.getString("claimed_by"),
            rs.getTimestamp("claimed_at") != null ? rs.getTimestamp("claimed_at").toInstant() : null,
            rs.getTimestamp("lease_expires_at") != null ? rs.getTimestamp("lease_expires_at").toInstant() : null,
            rs.getInt("attempt_count"),
            rs.getInt("max_attempts"),
            rs.getString("payload"),
            rs.getString("result_metadata"),
            rs.getString("error_detail"),
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public ScanJobRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public ScanJob insert(UUID scanRunId, UUID targetId, String moduleType, String payloadJson) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO scan_jobs (id, scan_run_id, target_id, module_type, payload) VALUES (?, ?, ?, ?, ?::jsonb)",
                id,
                scanRunId,
                targetId,
                moduleType,
                payloadJson);
        return findById(id).orElseThrow();
    }

    /**
     * Inserts a job already in its terminal COMPLETE state - for scan_runs
     * whose "work" is computed synchronously by central-server itself rather
     * than dispatched to a worker (e.g. VulnerabilityCorrelationScheduler's
     * per-target finding synthesis), where there's no claim/execute/report
     * lifecycle to model, just a bookkeeping row so
     * {@link ScanRunService#checkAndCompleteRun} finds a real terminal job
     * and completes the run/triggers scoring, the same as every other run.
     */
    public ScanJob insertComplete(UUID scanRunId, UUID targetId, String moduleType) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO scan_jobs (id, scan_run_id, target_id, module_type, status) VALUES (?, ?, ?, ?, 'COMPLETE')",
                id,
                scanRunId,
                targetId,
                moduleType);
        return findById(id).orElseThrow();
    }

    public Optional<ScanJob> findById(UUID id) {
        return jdbc.query("SELECT * FROM scan_jobs WHERE id = ?", ROW_MAPPER, id).stream()
                .findFirst();
    }

    /**
     * The authorization check for {@link org.freedonia.bloodhound.server.jobqueue.JobLifecycleService#result}
     * - a security review found that endpoint fetched the job via the plain, ownership-blind
     * {@link #findById} and ingested findings/subdomains/fingerprints against its targetId BEFORE
     * ever checking that the caller actually held this job's lease (the {@code claimed_by}/status
     * check only happened at the very end, via {@link #complete}, by which point the ingest had
     * already run). Since {@code workerId} is caller-supplied and every worker shares one
     * {@code WORKER_API_KEY}, that meant anyone holding the key could ingest (including an empty
     * findings list, which {@code FindingReconciler} treats as "resolve every currently-open
     * finding") against ANY org's job by id, real claim or not.
     *
     * <p>{@code FOR UPDATE} - not a plain SELECT - so the row stays locked for the rest of the
     * caller's transaction: nothing else (concurrently, the lease reaper reassigning an
     * expired lease) can change this job's claimed_by/status between this check and the
     * eventual {@link #complete} call, closing the narrower timing race a check-then-later-write
     * without a held lock would still leave open.
     */
    public Optional<ScanJob> findByIdOwnedByForUpdate(UUID id, String workerId) {
        return jdbc.query(
                        "SELECT * FROM scan_jobs WHERE id = ? AND claimed_by = ? "
                                + "AND status IN ('CLAIMED', 'RUNNING') FOR UPDATE",
                        ROW_MAPPER,
                        id,
                        workerId)
                .stream()
                .findFirst();
    }

    public List<ScanJob> findByScanRunId(UUID scanRunId) {
        return jdbc.query("SELECT * FROM scan_jobs WHERE scan_run_id = ? ORDER BY created_at", ROW_MAPPER, scanRunId);
    }

    /**
     * Whether this run queued any job of a module type in the given set - used by the Targets
     * list to say "last scan: regular / deep" without fetching every job row just to check
     * membership (see ScanRunService#isTier2ModuleType, the single source of truth for which
     * module types count as Tier 2).
     */
    public boolean existsForRunWithModuleTypeIn(UUID scanRunId, List<String> moduleTypes) {
        if (moduleTypes.isEmpty()) {
            return false;
        }
        String placeholders = moduleTypes.stream().map(m -> "?").collect(java.util.stream.Collectors.joining(","));
        Object[] args = new Object[moduleTypes.size() + 1];
        args[0] = scanRunId;
        for (int i = 0; i < moduleTypes.size(); i++) {
            args[i + 1] = moduleTypes.get(i);
        }
        Boolean exists = jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM scan_jobs WHERE scan_run_id = ? AND module_type IN (" + placeholders + "))",
                Boolean.class,
                args);
        return Boolean.TRUE.equals(exists);
    }

    /**
     * True if this target already has a not-yet-finished job of this module
     * type sitting in the queue (PENDING, CLAIMED, or RUNNING) - used by
     * callers that dispatch on their own fixed schedule (CtMonitorScheduler)
     * to skip enqueuing a redundant duplicate rather than piling another one
     * on top of a job that hasn't been picked up yet. COMPLETE/FAILED don't
     * count - those are finished, a fresh job for the next cycle is exactly
     * the point.
     */
    public boolean existsNonTerminal(UUID targetId, String moduleType) {
        Boolean exists = jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM scan_jobs WHERE target_id = ? AND module_type = ? "
                        + "AND status IN ('PENDING', 'CLAIMED', 'RUNNING'))",
                Boolean.class,
                targetId,
                moduleType);
        return Boolean.TRUE.equals(exists);
    }

    /**
     * Atomically claims up to {@code capacity} PENDING, due jobs for this
     * worker. The CTE + FOR UPDATE SKIP LOCKED + UPDATE ... RETURNING pattern
     * is a single statement, so it's already atomic without needing an
     * explicit transaction: concurrent callers each lock a disjoint row set
     * (SKIP LOCKED) and only the rows *this* statement locked get updated and
     * returned - no two workers can ever be handed the same job.
     */
    public List<ScanJob> claim(String workerId, int capacity, int leaseMinutes) {
        String sql =
                """
                WITH claimed AS (
                    SELECT id FROM scan_jobs
                    WHERE status = 'PENDING' AND run_after <= now()
                      AND (
                          module_type != 'ZAP_ACTIVE_SCAN'
                          OR (SELECT count(*) FROM scan_jobs WHERE module_type = 'ZAP_ACTIVE_SCAN' AND status IN ('CLAIMED', 'RUNNING')) < ?
                      )
                    ORDER BY priority DESC, created_at ASC
                    LIMIT ?
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE scan_jobs sj
                SET status = 'CLAIMED', claimed_by = ?, claimed_at = now(),
                    lease_expires_at = now() + make_interval(mins => ?)
                FROM claimed
                WHERE sj.id = claimed.id
                RETURNING sj.*
                """;
        return jdbc.query(sql, ROW_MAPPER, zapMaxConcurrentScans, capacity, workerId, leaseMinutes);
    }

    /** Returns true iff a matching, still-leased job was found and extended. */
    public boolean heartbeat(UUID id, String workerId, int leaseMinutes) {
        int updated = jdbc.update(
                "UPDATE scan_jobs SET status = CASE WHEN status = 'CLAIMED' THEN 'RUNNING' ELSE status END, "
                        + "lease_expires_at = now() + make_interval(mins => ?) "
                        + "WHERE id = ? AND claimed_by = ? AND status IN ('CLAIMED', 'RUNNING')",
                leaseMinutes,
                id,
                workerId);
        return updated == 1;
    }

    /** Returns true iff a matching claimed job was found and marked COMPLETE. */
    public boolean complete(UUID id, String workerId, String resultMetadataJson) {
        int updated = jdbc.update(
                "UPDATE scan_jobs SET status = 'COMPLETE', result_metadata = ?::jsonb "
                        + "WHERE id = ? AND claimed_by = ? AND status IN ('CLAIMED', 'RUNNING')",
                resultMetadataJson,
                id,
                workerId);
        return updated == 1;
    }

    /**
     * Returns the job's new terminal-or-retry status ("PENDING" or "FAILED"),
     * or empty if no matching claimed job was found (unknown id / wrong
     * worker / already terminal).
     */
    public Optional<String> fail(UUID id, String workerId, String errorDetail) {
        Optional<ScanJob> jobOpt = jdbc.query(
                        "SELECT * FROM scan_jobs WHERE id = ? AND claimed_by = ? AND status IN ('CLAIMED', 'RUNNING')",
                        ROW_MAPPER,
                        id,
                        workerId)
                .stream()
                .findFirst();
        if (jobOpt.isEmpty()) {
            return Optional.empty();
        }
        ScanJob job = jobOpt.get();
        int nextAttempt = job.attemptCount() + 1;
        if (nextAttempt < job.maxAttempts()) {
            // Retry backoff: without this, a job that fails fast (e.g. an immediate DNS
            // resolution error) gets reset straight to PENDING and is picked up again on
            // the worker's very next poll cycle (a few seconds later) - all 3 attempts of
            // a doomed-to-fail job then burn through in well under a minute, hammering an
            // already-unreachable target for no benefit. backoffSeconds grows with attempt
            // number (30s, 120s, capped at 300s) - distinct from the lease reaper's own
            // retry path below, which handles jobs that got stuck/timed out rather than
            // ones that explicitly reported failure.
            jdbc.update(
                    "UPDATE scan_jobs SET status = 'PENDING', claimed_by = NULL, claimed_at = NULL, "
                            + "lease_expires_at = NULL, attempt_count = ?, error_detail = ?, "
                            + "run_after = now() + make_interval(secs => ?) WHERE id = ?",
                    nextAttempt,
                    errorDetail,
                    backoffSeconds(nextAttempt),
                    id);
            return Optional.of("PENDING");
        }
        jdbc.update(
                "UPDATE scan_jobs SET status = 'FAILED', attempt_count = ?, error_detail = ? WHERE id = ?",
                nextAttempt,
                errorDetail,
                id);
        return Optional.of("FAILED");
    }

    /**
     * Moves every not-yet-terminal job (PENDING/CLAIMED/RUNNING) of a run to CANCELLED - see
     * ScanRunService#cancel. A job a worker already claimed keeps executing (this queue has no
     * way to interrupt work already handed out), but its eventual {@link #complete}/{@link #fail}
     * report becomes a silent no-op once the job leaves CLAIMED/RUNNING here, since both of those
     * guard on exactly that status set.
     */
    public void cancelNonTerminalForRun(UUID scanRunId) {
        jdbc.update(
                "UPDATE scan_jobs SET status = 'CANCELLED' WHERE scan_run_id = ? AND status IN ('PENDING', 'CLAIMED', 'RUNNING')",
                scanRunId);
    }

    /** 30s after the 1st failure, 120s after the 2nd, capped at 300s for any later attempt. */
    static int backoffSeconds(int nextAttempt) {
        return switch (nextAttempt) {
            case 1 -> 30;
            case 2 -> 120;
            default -> 300;
        };
    }

    /** One job whose lease expired without a heartbeat/result - see {@link #reapExpiredLeases}. */
    public record ReapedJob(UUID jobId, UUID scanRunId, String newStatus, String workerId) {}

    /**
     * Resets or fails jobs whose lease expired without a heartbeat/result.
     * Returns every reaped job (not just ones that went FAILED) so the caller
     * can close out each one's in-flight attempt row as TIMED_OUT_REAPED
     * regardless of whether it's getting retried or is now terminal.
     */
    public List<ReapedJob> reapExpiredLeases() {
        // claimed_by is captured via the `expired` CTE *before* the UPDATE runs, since
        // the retry branch nulls the column out - RETURNING alone would only ever see
        // the post-update (already-NULL) value for a retried job, losing which worker
        // actually held it. Same CTE-snapshot-before-UPDATE shape claim() already uses.
        String sql =
                """
                WITH expired AS (
                    SELECT id, claimed_by FROM scan_jobs
                    WHERE status IN ('CLAIMED', 'RUNNING') AND lease_expires_at < now()
                )
                UPDATE scan_jobs sj
                SET status = CASE WHEN attempt_count + 1 < max_attempts THEN 'PENDING' ELSE 'FAILED' END,
                    claimed_by = CASE WHEN attempt_count + 1 < max_attempts THEN NULL ELSE sj.claimed_by END,
                    claimed_at = CASE WHEN attempt_count + 1 < max_attempts THEN NULL ELSE sj.claimed_at END,
                    lease_expires_at = CASE WHEN attempt_count + 1 < max_attempts THEN NULL ELSE sj.lease_expires_at END,
                    attempt_count = attempt_count + 1,
                    error_detail = 'lease expired without heartbeat/result'
                FROM expired
                WHERE sj.id = expired.id
                RETURNING sj.id, sj.scan_run_id, sj.status, expired.claimed_by AS original_claimed_by
                """;
        return jdbc.query(
                sql,
                (rs, rowNum) -> new ReapedJob(
                        UUID.fromString(rs.getString("id")),
                        UUID.fromString(rs.getString("scan_run_id")),
                        rs.getString("status"),
                        rs.getString("original_claimed_by")));
    }
}
