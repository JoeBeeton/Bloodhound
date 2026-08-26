package org.freedonia.bloodhound.server.auth;

import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class WorkerCredentialRepository {

    private static final RowMapper<WorkerCredential> ROW_MAPPER = (rs, rowNum) -> new WorkerCredential(
            UUID.fromString(rs.getString("id")),
            rs.getString("label"),
            rs.getString("api_key_hash"),
            rs.getTimestamp("revoked_at") != null ? rs.getTimestamp("revoked_at").toInstant() : null);

    private final JdbcTemplate jdbc;

    public WorkerCredentialRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean existsByKeyHash(String apiKeyHash) {
        Long count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM worker_credentials WHERE api_key_hash = ?", Long.class, apiKeyHash);
        return count != null && count > 0;
    }

    /** Returns the credential only if it exists and hasn't been revoked. */
    public Optional<WorkerCredential> findActiveByKeyHash(String apiKeyHash) {
        return jdbc.query("SELECT * FROM worker_credentials WHERE api_key_hash = ?", ROW_MAPPER, apiKeyHash).stream()
                .findFirst()
                .filter(c -> c.revokedAt() == null);
    }

    public void insert(String label, String apiKeyHash) {
        jdbc.update(
                "INSERT INTO worker_credentials (id, label, api_key_hash) VALUES (?, ?, ?)",
                UUID.randomUUID(),
                label,
                apiKeyHash);
    }
}
