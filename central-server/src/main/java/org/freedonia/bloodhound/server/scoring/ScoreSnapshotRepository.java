package org.freedonia.bloodhound.server.scoring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Append-only: score_snapshots rows are only ever inserted, never updated or deleted. */
@Repository
public class ScoreSnapshotRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public ScoreSnapshotRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    private final RowMapper<ScoreSnapshot> rowMapper = (rs, rowNum) -> new ScoreSnapshot(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            UUID.fromString(rs.getString("scan_run_id")),
            rs.getTimestamp("computed_at").toInstant(),
            rs.getBigDecimal("overall_score"),
            rs.getString("grade"),
            readMap(rs.getString("category_scores"), new TypeReference<Map<String, BigDecimal>>() {}),
            readMap(rs.getString("finding_counts"), new TypeReference<Map<String, Long>>() {}),
            rs.getBigDecimal("tier1_overall_score"),
            rs.getString("tier1_grade"),
            readMapOrNull(rs.getString("tier1_category_scores"), new TypeReference<Map<String, BigDecimal>>() {}));

    /** Persists both the full score and the Tier-1-only "fair comparison" score from the same scan run. */
    public ScoreSnapshot insert(UUID targetId, UUID scanRunId, ScoreResult full, ScoreResult tier1Only) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO score_snapshots (id, target_id, scan_run_id, overall_score, grade, category_scores, "
                        + "finding_counts, tier1_overall_score, tier1_grade, tier1_category_scores) "
                        + "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?::jsonb)",
                id,
                targetId,
                scanRunId,
                full.overallScore(),
                full.grade(),
                writeJson(full.categoryScores()),
                writeJson(full.findingCounts()),
                tier1Only.overallScore(),
                tier1Only.grade(),
                writeJson(tier1Only.categoryScores()));
        return findById(id).orElseThrow();
    }

    public Optional<ScoreSnapshot> findById(UUID id) {
        return jdbc.query("SELECT * FROM score_snapshots WHERE id = ?", rowMapper, id).stream()
                .findFirst();
    }

    public List<ScoreSnapshot> findHistory(UUID targetId, Instant from, Instant to) {
        return jdbc.query(
                "SELECT * FROM score_snapshots WHERE target_id = ? AND computed_at >= ? AND computed_at <= ? "
                        + "ORDER BY computed_at ASC",
                rowMapper,
                targetId,
                java.sql.Timestamp.from(from),
                java.sql.Timestamp.from(to));
    }

    /** Most recent snapshot for a target, if any scan has ever completed - used to decorate target list/detail responses. */
    public Optional<ScoreSnapshot> findLatest(UUID targetId) {
        return jdbc.query(
                        "SELECT * FROM score_snapshots WHERE target_id = ? ORDER BY computed_at DESC LIMIT 1",
                        rowMapper,
                        targetId)
                .stream()
                .findFirst();
    }

    private <T> T readMap(String json, TypeReference<T> type) {
        try {
            return objectMapper.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to deserialize score_snapshots jsonb column", e);
        }
    }

    /** Same as {@link #readMap}, but tolerant of a NULL column - true for tier1_category_scores on any snapshot taken before this was added. */
    private <T> T readMapOrNull(String json, TypeReference<T> type) {
        return json == null ? null : readMap(json, type);
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize score result", e);
        }
    }
}
