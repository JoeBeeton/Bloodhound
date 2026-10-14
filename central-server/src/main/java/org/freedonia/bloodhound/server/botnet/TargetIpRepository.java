package org.freedonia.bloodhound.server.botnet;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Every active target's currently-known IP addresses, sourced from {@code subdomains.current_ip_addresses} - the same per-host IP data the WAF-badge/attack-surface-graph features already read. */
@Repository
public class TargetIpRepository {

    public record Candidate(UUID targetId, String hostname, String ipAddress) {}

    private final JdbcTemplate jdbc;

    public TargetIpRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * CROSS JOIN, not a comma-join-then-JOIN: a comma-join followed by a regular JOIN referencing
     * the comma-joined table throws "invalid reference to FROM-clause entry" in Postgres (a real
     * bug already hit once this session in EolReleaseCacheRepository.findEolCandidates, fixed the
     * same way there).
     */
    public List<Candidate> findAllActiveTargetIps() {
        return jdbc.query(
                """
                SELECT s.target_id, s.hostname, ip.value AS ip_address
                FROM subdomains s
                CROSS JOIN jsonb_array_elements_text(s.current_ip_addresses) AS ip(value)
                JOIN targets t ON t.id = s.target_id
                WHERE t.is_active = true AND s.is_active = true
                """,
                (rs, rowNum) -> new Candidate(
                        UUID.fromString(rs.getString("target_id")), rs.getString("hostname"), rs.getString("ip_address")));
    }
}
