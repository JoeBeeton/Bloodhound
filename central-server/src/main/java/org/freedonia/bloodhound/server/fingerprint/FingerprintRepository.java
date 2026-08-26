package org.freedonia.bloodhound.server.fingerprint;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Owns the fingerprints table: a current-state snapshot per (target, hostname),
 * upserted on every TECH_FINGERPRINT run - unlike whois_records this deliberately
 * keeps no history, see the V11 migration comment for why.
 */
@Repository
public class FingerprintRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public FingerprintRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    private final RowMapper<Fingerprint> rowMapper = (rs, rowNum) -> new Fingerprint(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getString("hostname"),
            parseTechnologies(rs.getString("technologies")),
            rs.getString("hosting_provider"),
            rs.getString("hosting_asn"),
            rs.getString("hosting_asn_org"),
            rs.getTimestamp("captured_at").toInstant());

    public List<Fingerprint> findByTarget(UUID targetId) {
        return jdbc.query(
                "SELECT * FROM fingerprints WHERE target_id = ? ORDER BY hostname", rowMapper, targetId);
    }

    public void upsert(
            UUID targetId,
            String hostname,
            List<Technology> technologies,
            String hostingProvider,
            String hostingAsn,
            String hostingAsnOrg) {
        jdbc.update(
                """
                INSERT INTO fingerprints (id, target_id, hostname, technologies, hosting_provider, hosting_asn, hosting_asn_org, captured_at)
                VALUES (?, ?, ?, ?::jsonb, ?, ?, ?, now())
                ON CONFLICT (target_id, hostname) DO UPDATE
                SET technologies = EXCLUDED.technologies, hosting_provider = EXCLUDED.hosting_provider,
                    hosting_asn = EXCLUDED.hosting_asn, hosting_asn_org = EXCLUDED.hosting_asn_org, captured_at = now()
                """,
                UUID.randomUUID(),
                targetId,
                hostname,
                writeJson(technologies),
                hostingProvider,
                hostingAsn,
                hostingAsnOrg);
    }

    private List<Technology> parseTechnologies(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            return List.of();
        }
    }

    private String writeJson(List<Technology> technologies) {
        try {
            return objectMapper.writeValueAsString(technologies == null ? List.of() : technologies);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize fingerprint technologies", e);
        }
    }
}
