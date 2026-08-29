package org.freedonia.bloodhound.server.jobqueue;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * The full per-attempt retry history for a scan_job - see V22 for why this exists
 * alongside scan_jobs' own (overwritten-on-retry) attempt_count/error_detail columns.
 */
@Repository
public class ScanJobAttemptRepository {

    private static final RowMapper<ScanJobAttempt> ROW_MAPPER = (rs, rowNum) -> new ScanJobAttempt(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("scan_job_id")),
            rs.getInt("attempt_number"),
            rs.getString("claimed_by"),
            rs.getTimestamp("started_at").toInstant(),
            rs.getTimestamp("ended_at") != null ? rs.getTimestamp("ended_at").toInstant() : null,
            rs.getString("outcome"),
            rs.getString("error_detail"),
            rs.getString("log_output"));

    private final JdbcTemplate jdbc;

    public ScanJobAttemptRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Logged when a worker claims a job - attemptNumber is the scan_jobs.attempt_count *before* this try, +1 (1-indexed). */
    public void startAttempt(UUID scanJobId, int attemptNumber, String claimedBy) {
        jdbc.update(
                "INSERT INTO scan_job_attempts (id, scan_job_id, attempt_number, claimed_by) VALUES (?, ?, ?, ?)",
                UUID.randomUUID(),
                scanJobId,
                attemptNumber,
                claimedBy);
    }

    /**
     * Closes out the most recent still-open (outcome IS NULL) attempt row for this job -
     * there's exactly one at a time by construction (a job is only ever claimed once
     * before its current attempt is closed out, one way or another).
     */
    public void completeAttempt(UUID scanJobId, String outcome, String errorDetail, String logOutput) {
        jdbc.update(
                """
                UPDATE scan_job_attempts SET ended_at = now(), outcome = ?, error_detail = ?, log_output = ?
                WHERE id = (
                    SELECT id FROM scan_job_attempts
                    WHERE scan_job_id = ? AND outcome IS NULL
                    ORDER BY attempt_number DESC LIMIT 1
                )
                """,
                outcome,
                errorDetail,
                logOutput,
                scanJobId);
    }

    public List<ScanJobAttempt> findByScanJobId(UUID scanJobId) {
        return jdbc.query(
                "SELECT * FROM scan_job_attempts WHERE scan_job_id = ? ORDER BY attempt_number ASC",
                ROW_MAPPER,
                scanJobId);
    }

    /**
     * Average real (started_at -> ended_at) duration per module_type, from up to
     * {@code sampleSize} of the most recent successful completions of that type -
     * the historical basis {@link ScanEtaEstimator} uses. Only SUCCESS attempts count:
     * a FAILED/TIMED_OUT_REAPED attempt's duration reflects how long it took to give up,
     * not how long the module actually takes to run, and would skew the estimate.
     */
    public java.util.Map<String, Double> averageSecondsByModuleType(int sampleSize) {
        String sql =
                """
                SELECT module_type, AVG(EXTRACT(EPOCH FROM (a.ended_at - a.started_at))) AS avg_seconds
                FROM (
                    SELECT sja.*, sj.module_type,
                           ROW_NUMBER() OVER (PARTITION BY sj.module_type ORDER BY sja.ended_at DESC) AS rn
                    FROM scan_job_attempts sja
                    JOIN scan_jobs sj ON sj.id = sja.scan_job_id
                    WHERE sja.outcome = 'SUCCESS' AND sja.ended_at IS NOT NULL
                ) a
                WHERE a.rn <= ?
                GROUP BY module_type
                """;
        java.util.Map<String, Double> result = new java.util.HashMap<>();
        jdbc.query(sql, rs -> {
            result.put(rs.getString("module_type"), rs.getDouble("avg_seconds"));
        }, sampleSize);
        return result;
    }
}
