package org.freedonia.bloodhound.server.subdomain;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Owns the subdomains table: the discovered-hostname upsert and the target-scoped listing query. */
@Repository
public class SubdomainRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public SubdomainRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    private final RowMapper<Subdomain> rowMapper = (rs, rowNum) -> new Subdomain(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("target_id")),
            rs.getString("hostname"),
            rs.getTimestamp("first_seen_at").toInstant(),
            rs.getTimestamp("last_seen_at").toInstant(),
            rs.getString("source"),
            rs.getBoolean("is_active"),
            parseIps(rs.getString("current_ip_addresses")),
            rs.getString("dangling_cname_target"));

    /** Hostnames already tracked for this target, regardless of liveness - used to decide "genuinely new" on ingestion. */
    public Set<String> findHostnames(UUID targetId) {
        return new HashSet<>(jdbc.queryForList("SELECT hostname FROM subdomains WHERE target_id = ?", String.class, targetId));
    }

    /**
     * Hostnames to include in a fanned-out scan payload, capped at {@code
     * limit} - ordered so subdomains never yet included in a fanout payload
     * (last_scanned_at is null) come first, then least-recently-included
     * ones, so a target with more subdomains than the cap still gets full
     * coverage over enough scan cycles instead of the same subset forever.
     * hostname is a secondary sort only to make ordering deterministic
     * among ties (many hostnames sharing the same last_scanned_at, most
     * commonly many nulls at once); it carries no scanning priority itself.
     * Capping in SQL (rather than the caller truncating an unordered
     * in-memory collection, as this used to do) makes "capped" and
     * "correctly prioritized" the same guarantee instead of two separate
     * ones that can drift apart.
     *
     * <p>Restricted to is_active = true: a subdomain that no longer resolves (the most
     * recent SUBDOMAIN_ENUM run couldn't find an IP for it) will never successfully be
     * scanned - fanning out to it anyway just wastes a job slot on a guaranteed failure
     * (confirmed for real: a Tier 2 ZAP job against a non-resolving host fails all 3
     * attempts with a confusing "ZAP API returned HTTP 400", since ZAP's spider can't
     * reach it either, rather than a useful "host unreachable" message). Excluding dead
     * hosts here also means the rotation naturally spends its limited per-cycle slots on
     * hosts that can actually produce a real result.
     */
    public List<String> findHostnamesForFanout(UUID targetId, int limit) {
        return jdbc.queryForList(
                "SELECT hostname FROM subdomains WHERE target_id = ? AND is_active = true "
                        + "ORDER BY last_scanned_at ASC NULLS FIRST, hostname ASC LIMIT ?",
                String.class,
                targetId,
                limit);
    }

    /**
     * Marks exactly the given hostnames as just-included in a fanout
     * payload, advancing the rotation {@link #findHostnamesForFanout} reads
     * next time. Called only after the corresponding scan_jobs have actually
     * been created (see ScanRunService) - if job creation throws partway
     * through, execution never reaches this call, so a hostname is never
     * marked scanned for work that didn't actually get queued.
     */
    public void markScanned(UUID targetId, List<String> hostnames) {
        if (hostnames.isEmpty()) {
            return;
        }
        // Dynamic IN (...) placeholders, not ANY(?): plain JdbcTemplate.update
        // binds a bare Object[]/List argument via PreparedStatement.setObject,
        // which the Postgres JDBC driver does not implicitly convert to a SQL
        // array for ANY(?) - that needs an explicit java.sql.Array via
        // Connection.createArrayOf. Same IN-clause-placeholder-building
        // pattern KevCatalogRepository.findMatching already uses.
        String placeholders = hostnames.stream().map(h -> "?").collect(Collectors.joining(","));
        Object[] args = new Object[hostnames.size() + 1];
        args[0] = targetId;
        for (int i = 0; i < hostnames.size(); i++) {
            args[i + 1] = hostnames.get(i);
        }
        jdbc.update(
                "UPDATE subdomains SET last_scanned_at = now() WHERE target_id = ? AND hostname IN (" + placeholders
                        + ")",
                args);
    }

    /**
     * Insert-or-refresh: a hostname seen for the first time gets a new row
     * (first_seen_at = now); one already tracked just has last_seen_at,
     * source, resolved IPs, and dangling-CNAME status refreshed, without
     * disturbing first_seen_at. dangling_cname_target is always overwritten
     * (including back to null) so a subdomain that's no longer dangling
     * (CNAME changed, or the resource was reclaimed) clears on the next scan
     * rather than keeping a stale "dangling" marker forever.
     *
     * <p>is_active reflects whether this run's own DNS resolution attempt for
     * this hostname actually returned any IP - not whether an enumeration
     * source rediscovered it (a source outage, e.g. crt.sh's documented
     * flakiness, would otherwise falsely look like every subdomain went
     * stale). Derived from ipAddresses being non-empty; see
     * SubdomainIngestionService for the SUBDOMAIN_STALE_NOT_RESOLVING
     * finding this state transition drives.
     */
    public void upsert(UUID targetId, String hostname, String source, List<String> ipAddresses, String danglingCnameTarget) {
        boolean isActive = !ipAddresses.isEmpty();
        jdbc.update(
                """
                INSERT INTO subdomains (id, target_id, hostname, source, current_ip_addresses, is_active, dangling_cname_target)
                VALUES (?, ?, ?, ?, ?::jsonb, ?, ?)
                ON CONFLICT (target_id, hostname) DO UPDATE
                SET last_seen_at = now(), current_ip_addresses = EXCLUDED.current_ip_addresses, is_active = EXCLUDED.is_active,
                    source = EXCLUDED.source, dangling_cname_target = EXCLUDED.dangling_cname_target
                """,
                UUID.randomUUID(),
                targetId,
                hostname,
                source,
                writeIps(ipAddresses),
                isActive,
                danglingCnameTarget);
    }

    public List<Subdomain> findByTarget(UUID targetId) {
        return jdbc.query(
                "SELECT * FROM subdomains WHERE target_id = ? ORDER BY hostname ASC", rowMapper, targetId);
    }

    /**
     * Subdomains first seen at or after a scan_run's start - backs the NEW_SUBDOMAINS
     * notification's batched count (see notification.NotificationService). Time-window
     * based rather than a direct scan_run_id foreign key (subdomains has no such
     * column, and SUBDOMAIN_ENUM runs at most once per scan_run in practice, so this is
     * an accurate-enough correlation for a notification count without a schema change).
     */
    public int countNewSince(UUID targetId, java.time.Instant runStartedAt) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM subdomains WHERE target_id = ? AND first_seen_at >= ?",
                Integer.class,
                targetId,
                java.sql.Timestamp.from(runStartedAt));
        return count != null ? count : 0;
    }

    private List<String> parseIps(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return List.of();
        }
    }

    private String writeIps(List<String> ips) {
        try {
            return objectMapper.writeValueAsString(ips == null ? List.of() : ips);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize subdomain IP list", e);
        }
    }
}
