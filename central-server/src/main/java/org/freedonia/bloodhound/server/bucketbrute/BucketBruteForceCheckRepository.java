package org.freedonia.bloodhound.server.bucketbrute;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Owns the bucket_brute_force_checks table: a current-state snapshot per
 * (target, candidate_name, provider), upserted on every BUCKET_BRUTE_FORCE
 * run - same current-state-not-history shape as typosquat_candidates
 * (TyposquatCandidateRepository), since a candidate's listability is a live
 * fact, not something worth keeping a full timeline of. The whole point of
 * this table is letting {@link #findRecentlyCheckedKeys} answer "what have
 * we already tried lately" so ScanRunService can exclude those candidates
 * from the next deep scan's job payload, instead of re-issuing the same few
 * hundred requests against AWS/GCS/etc. on every re-run.
 */
@Repository
public class BucketBruteForceCheckRepository {

    private final JdbcTemplate jdbc;

    public BucketBruteForceCheckRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Every (candidate_name, provider) pair checked for this target within
     * {@code since}, as "candidateName|provider" composite keys - a plain
     * flat Set is all ScanRunService needs to build its exclusion payload,
     * not a full row-mapped domain object (there's no UI surface for this
     * table, unlike typosquat_candidates).
     */
    public Set<String> findRecentlyCheckedKeys(UUID targetId, Instant since) {
        List<String> rows = jdbc.query(
                "SELECT candidate_name, provider FROM bucket_brute_force_checks "
                        + "WHERE target_id = ? AND last_checked_at >= ?",
                (rs, rowNum) -> rs.getString("candidate_name") + "|" + rs.getString("provider"),
                targetId,
                java.sql.Timestamp.from(since));
        return new HashSet<>(rows);
    }

    /** Called once per (candidate, provider) the worker actually checked this run - see
     * BucketBruteForceIngestionService. Refreshes last_checked_at even when was_listable is
     * unchanged, which is exactly what advances the cooldown window for next time. */
    public void upsert(UUID targetId, String candidateName, String provider, boolean wasListable) {
        jdbc.update(
                """
                INSERT INTO bucket_brute_force_checks
                    (id, target_id, candidate_name, provider, was_listable, last_checked_at)
                VALUES (?, ?, ?, ?, ?, now())
                ON CONFLICT (target_id, candidate_name, provider) DO UPDATE
                SET was_listable = EXCLUDED.was_listable, last_checked_at = now()
                """,
                UUID.randomUUID(),
                targetId,
                candidateName,
                provider,
                wasListable);
    }
}
