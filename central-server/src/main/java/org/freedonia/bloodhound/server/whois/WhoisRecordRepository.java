package org.freedonia.bloodhound.server.whois;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Owns the append-only whois_records table: one insert per WHOIS module run, plus the "most recent row" lookup used to detect a registrar change. */
@Repository
public class WhoisRecordRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public WhoisRecordRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    private final RowMapper<WhoisRecord> rowMapper = (rs, rowNum) -> new WhoisRecord(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getTimestamp("captured_at").toInstant(),
            rs.getString("registrar"),
            rs.getTimestamp("created_date") != null ? rs.getTimestamp("created_date").toInstant() : null,
            rs.getTimestamp("expiry_date") != null ? rs.getTimestamp("expiry_date").toInstant() : null,
            rs.getString("registrant_org"),
            parseNameServers(rs.getString("name_servers")));

    public Optional<WhoisRecord> findLatest(UUID targetId) {
        return jdbc
                .query(
                        "SELECT * FROM whois_records WHERE target_id = ? ORDER BY captured_at DESC LIMIT 1",
                        rowMapper,
                        targetId)
                .stream()
                .findFirst();
    }

    public void insert(
            UUID targetId,
            String registrar,
            Instant createdDate,
            Instant expiryDate,
            String registrantOrg,
            List<String> nameServers,
            Object rawJsonb) {
        jdbc.update(
                "INSERT INTO whois_records "
                        + "(id, target_id, registrar, created_date, expiry_date, registrant_org, name_servers, raw_jsonb) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb)",
                UUID.randomUUID(),
                targetId,
                registrar,
                createdDate != null ? Timestamp.from(createdDate) : null,
                expiryDate != null ? Timestamp.from(expiryDate) : null,
                registrantOrg,
                writeJson(nameServers == null ? List.of() : nameServers),
                writeJson(rawJsonb == null ? java.util.Map.of() : rawJsonb));
    }

    private List<String> parseNameServers(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return List.of();
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize WHOIS record field", e);
        }
    }
}
