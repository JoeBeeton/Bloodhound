package org.freedonia.bloodhound.server.typosquat;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Owns the typosquat_candidates table: a current-state snapshot per (target,
 * candidate_domain), upserted on every TYPOSQUAT_MONITOR run - same
 * current-state-not-history shape as fingerprints, since a candidate's
 * registration status is a live fact, not something worth keeping a full
 * timeline of.
 */
@Repository
public class TyposquatCandidateRepository {

    private final JdbcTemplate jdbc;

    public TyposquatCandidateRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private final RowMapper<TyposquatCandidate> rowMapper = (rs, rowNum) -> new TyposquatCandidate(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getString("candidate_domain"),
            rs.getString("permutation_type"),
            rs.getTimestamp("first_seen_at").toInstant(),
            rs.getTimestamp("last_checked_at").toInstant(),
            rs.getBoolean("is_registered"),
            rs.getString("resolved_ip"),
            rs.getTimestamp("registration_date") == null ? null : rs.getTimestamp("registration_date").toInstant());

    public void upsert(
            UUID targetId,
            String candidateDomain,
            String permutationType,
            boolean isRegistered,
            String resolvedIp,
            Instant registrationDate) {
        jdbc.update(
                """
                INSERT INTO typosquat_candidates
                    (id, target_id, candidate_domain, permutation_type, is_registered, resolved_ip, registration_date, last_checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, now())
                ON CONFLICT (target_id, candidate_domain) DO UPDATE
                SET is_registered = EXCLUDED.is_registered, resolved_ip = EXCLUDED.resolved_ip,
                    registration_date = EXCLUDED.registration_date, permutation_type = EXCLUDED.permutation_type,
                    last_checked_at = now()
                """,
                UUID.randomUUID(),
                targetId,
                candidateDomain,
                permutationType,
                isRegistered,
                resolvedIp,
                registrationDate == null ? null : java.sql.Timestamp.from(registrationDate));
    }

    /** Only registered candidates - the only ones actionable in the UI; unregistered candidates are tracked for re-checking but not worth surfacing. */
    public List<TyposquatCandidate> findRegisteredByTarget(UUID targetId) {
        return jdbc.query(
                "SELECT * FROM typosquat_candidates WHERE target_id = ? AND is_registered = true ORDER BY first_seen_at DESC",
                rowMapper,
                targetId);
    }
}
