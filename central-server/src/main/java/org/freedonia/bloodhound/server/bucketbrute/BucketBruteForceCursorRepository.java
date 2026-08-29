package org.freedonia.bloodhound.server.bucketbrute;

import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Owns the bucket_brute_force_wordlist_cursor table: one row per target
 * recording how far a deep scan's BUCKET_BRUTE_FORCE job has swept through
 * {@code BucketNameGenerator}'s large wordlist. A current-state pointer, not
 * a history table - there's nothing worth keeping a timeline of, only "where
 * do we resume from next" (see ScanRunService#targetScopedPayload, which
 * reads {@link #currentPosition}, and BucketBruteForceIngestionService,
 * which calls {@link #advance} once the worker reports back how far it got).
 */
@Repository
public class BucketBruteForceCursorRepository {

    private final JdbcTemplate jdbc;

    public BucketBruteForceCursorRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** No row yet means this target has never run BUCKET_BRUTE_FORCE (or ran before this
     * cursor existed) - starting from the top of the wordlist (position 0) is the correct
     * default, not an error condition. */
    public int currentPosition(UUID targetId) {
        Integer position = jdbc.query(
                "SELECT position FROM bucket_brute_force_wordlist_cursor WHERE target_id = ?",
                rs -> rs.next() ? rs.getInt("position") : null,
                targetId);
        return position == null ? 0 : position;
    }

    public void advance(UUID targetId, int newPosition) {
        jdbc.update(
                """
                INSERT INTO bucket_brute_force_wordlist_cursor (target_id, position, updated_at)
                VALUES (?, ?, now())
                ON CONFLICT (target_id) DO UPDATE
                SET position = EXCLUDED.position, updated_at = now()
                """,
                targetId,
                newPosition);
    }
}
