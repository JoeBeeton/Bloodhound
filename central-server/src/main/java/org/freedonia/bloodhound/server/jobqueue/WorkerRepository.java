package org.freedonia.bloodhound.server.jobqueue;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Presence/current-job bookkeeping for workers - see the `workers` table's own comment for why this needs no new worker-side call. */
@Repository
public class WorkerRepository {

    private static final RowMapper<WorkerRow> ROW_MAPPER = (rs, rowNum) -> new WorkerRow(
            rs.getString("worker_id"),
            rs.getTimestamp("last_heartbeat_at").toInstant(),
            rs.getString("current_job_id") != null ? UUID.fromString(rs.getString("current_job_id")) : null,
            rs.getString("module_type"),
            rs.getString("target_id") != null ? UUID.fromString(rs.getString("target_id")) : null,
            rs.getString("hostname"),
            rs.getString("organization_id") != null ? UUID.fromString(rs.getString("organization_id")) : null,
            rs.getString("current_host"));

    private final JdbcTemplate jdbc;

    public WorkerRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Called on every /jobs/claim request, whether or not it results in an actual claim - that's what makes an idle worker still show up as online. */
    public void heartbeat(String workerId) {
        jdbc.update(
                """
                INSERT INTO workers (worker_id, first_seen_at, last_heartbeat_at)
                VALUES (?, now(), now())
                ON CONFLICT (worker_id) DO UPDATE SET last_heartbeat_at = now()
                """,
                workerId);
    }

    public void setCurrentJob(String workerId, UUID jobId) {
        jdbc.update("UPDATE workers SET current_job_id = ? WHERE worker_id = ?", jobId, workerId);
    }

    /** Matched by workerId AND the specific jobId, not workerId alone, so a race can't clear a *different* job's ownership out from under it. */
    public void clearCurrentJob(String workerId, UUID jobId) {
        jdbc.update(
                "UPDATE workers SET current_job_id = NULL WHERE worker_id = ? AND current_job_id = ?",
                workerId,
                jobId);
    }

    /**
     * {@code current_host} is only present for Tier 2 jobs (one job per host, see
     * ScanRunService#createDeepScan) - Tier 1 jobs carry a multi-host {@code {"subdomains": [...]}}
     * payload instead, so this is null for those, which is correct: there's no single "the host"
     * to name for a job that's internally working through many.
     */
    public List<WorkerRow> findAllWithJobDetail() {
        return jdbc.query(
                """
                SELECT w.worker_id, w.last_heartbeat_at, w.current_job_id,
                       sj.module_type, sj.target_id, t.hostname, t.organization_id,
                       sj.payload->>'host' AS current_host
                FROM workers w
                LEFT JOIN scan_jobs sj ON sj.id = w.current_job_id AND sj.status IN ('CLAIMED', 'RUNNING')
                LEFT JOIN targets t ON t.id = sj.target_id
                ORDER BY w.worker_id
                """,
                ROW_MAPPER);
    }
}
