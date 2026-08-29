package org.freedonia.bloodhound.server.vuln;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * The shared-across-all-targets NVD/KEV result cache, keyed on
 * (technology_name, version) - not per target, since many different scanned
 * hosts commonly run the same software version. See the V13 migration
 * comment for why this matters for NVD's rate limit.
 */
@Repository
public class CveLookupCacheRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public CveLookupCacheRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    /**
     * Distinct (technology, version) pairs observed across ANY target's
     * fingerprints that are either not yet cached at all, or whose cache
     * entry is older than {@code staleAfter} - capped at {@code limit} to
     * respect NVD's rate limit per scheduler tick (see
     * VulnerabilityCorrelationScheduler).
     */
    public List<TechVersionPair> findPendingPairs(Duration staleAfter, int limit) {
        return jdbc.query(
                """
                SELECT DISTINCT tech->>'name' AS technology_name, tech->>'version' AS version
                FROM fingerprints, jsonb_array_elements(technologies) AS tech
                WHERE tech->>'version' IS NOT NULL AND tech->>'version' != ''
                  AND NOT EXISTS (
                      SELECT 1 FROM cve_lookup_cache c
                      WHERE c.technology_name = tech->>'name' AND c.version = tech->>'version'
                        AND c.checked_at > now() - (?::interval)
                  )
                LIMIT ?
                """,
                (rs, rowNum) -> new TechVersionPair(rs.getString("technology_name"), rs.getString("version")),
                staleAfter.toSeconds() + " seconds",
                limit);
    }

    public void upsert(String technologyName, String version, List<String> cveIds, List<String> kevMatches, String maxSeverity) {
        jdbc.update(
                """
                INSERT INTO cve_lookup_cache (id, technology_name, version, cve_ids, kev_matches, max_severity, checked_at)
                VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, now())
                ON CONFLICT (technology_name, version) DO UPDATE
                SET cve_ids = EXCLUDED.cve_ids, kev_matches = EXCLUDED.kev_matches,
                    max_severity = EXCLUDED.max_severity, checked_at = now()
                """,
                UUID.randomUUID(),
                technologyName,
                version,
                writeJson(cveIds),
                writeJson(kevMatches),
                maxSeverity);
    }

    /** Every currently-fingerprinted (target, hostname) whose detected (technology, version) has a real cached CVE match - the direct input to finding synthesis. Re-derived fresh on every scheduler tick (re-ingesting an unchanged finding is a cheap, idempotent no-op via the normal FindingReconciler dedup path) - but see {@link #maxCheckedAtByTarget}, which is what actually gates whether the scheduler creates a new scan_run/notification for a target this tick, since the ingestion path being idempotent doesn't make repeating the scan_run/notify side effects harmless. */
    public List<MatchedFingerprint> findMatchedFingerprints() {
        return jdbc.query(
                """
                SELECT DISTINCT f.target_id, f.hostname, c.technology_name, c.version, c.cve_ids, c.kev_matches, c.max_severity
                FROM fingerprints f
                CROSS JOIN jsonb_array_elements(f.technologies) AS tech
                JOIN cve_lookup_cache c
                    ON c.technology_name = tech->>'name' AND c.version = tech->>'version'
                JOIN targets t ON t.id = f.target_id
                WHERE jsonb_array_length(c.cve_ids) > 0 AND t.is_active = true
                """,
                (rs, rowNum) -> new MatchedFingerprint(
                        UUID.fromString(rs.getString("target_id")),
                        rs.getString("hostname"),
                        rs.getString("technology_name"),
                        rs.getString("version"),
                        readStringList(rs.getString("cve_ids")),
                        readStringList(rs.getString("kev_matches")),
                        rs.getString("max_severity")));
    }

    /**
     * For every target with at least one currently-matched fingerprint, the most recent {@code
     * checked_at} among its matches - lets {@link VulnerabilityCorrelationScheduler} tell "this
     * target's match set hasn't changed since I last synthesized findings for it" from "there's a
     * genuinely newer CVE/KEV match", so it only creates a new scan_run (and notifies) when
     * something has actually changed, not on every scheduler tick. {@code checked_at} only moves
     * when {@link #upsert} actually runs for a (technology, version) pair - see {@link
     * #findPendingPairs}'s staleness gate - so this is stable between real NVD re-checks, not a
     * constantly-advancing clock.
     */
    public java.util.Map<UUID, java.time.Instant> maxCheckedAtByTarget() {
        return jdbc.query(
                """
                SELECT f.target_id, MAX(c.checked_at) AS max_checked_at
                FROM fingerprints f
                CROSS JOIN jsonb_array_elements(f.technologies) AS tech
                JOIN cve_lookup_cache c
                    ON c.technology_name = tech->>'name' AND c.version = tech->>'version'
                JOIN targets t ON t.id = f.target_id
                WHERE jsonb_array_length(c.cve_ids) > 0 AND t.is_active = true
                GROUP BY f.target_id
                """,
                rs -> {
                    java.util.Map<UUID, java.time.Instant> result = new java.util.HashMap<>();
                    while (rs.next()) {
                        result.put(UUID.fromString(rs.getString("target_id")), rs.getTimestamp("max_checked_at").toInstant());
                    }
                    return result;
                });
    }

    private List<String> readStringList(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            return List.of();
        }
    }

    private String writeJson(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values == null ? List.of() : values);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize CVE id list", e);
        }
    }
}
