package org.freedonia.bloodhound.server.vuln;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Global cache of CVE descriptions from osv.dev, keyed only on cve_id (see V19 migration). */
@Repository
public class CveDetailsRepository {

    private final JdbcTemplate jdbc;

    public CveDetailsRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Distinct CVE IDs referenced by cve_lookup_cache (either as a plain CVE or a KEV match) that don't yet have a cve_details row - the input to a "fetch if missing" pass, capped since OSV, while generously rate-limited, still shouldn't be hammered unboundedly in one tick. */
    public List<String> findMissingCveIds(int limit) {
        return jdbc.queryForList(
                """
                SELECT DISTINCT cve_id FROM (
                    SELECT jsonb_array_elements_text(cve_ids) AS cve_id FROM cve_lookup_cache
                    UNION
                    SELECT jsonb_array_elements_text(kev_matches) AS cve_id FROM cve_lookup_cache
                ) all_ids
                WHERE NOT EXISTS (SELECT 1 FROM cve_details d WHERE d.cve_id = all_ids.cve_id)
                LIMIT ?
                """,
                String.class,
                limit);
    }

    public void upsert(OsvCveDetail detail) {
        jdbc.update(
                """
                INSERT INTO cve_details (cve_id, description, severity, published_date, source, fetched_at)
                VALUES (?, ?, ?, ?, 'osv.dev', now())
                ON CONFLICT (cve_id) DO UPDATE
                SET description = EXCLUDED.description, severity = EXCLUDED.severity,
                    published_date = EXCLUDED.published_date, fetched_at = now()
                """,
                detail.cveId(),
                detail.description(),
                detail.severity(),
                detail.publishedDate() == null ? null : Timestamp.from(detail.publishedDate()));
    }

    /** Cached details for exactly these CVE IDs (a finding's own cveIds/kevCveIds), for embedding into that finding's evidence. Silently omits IDs with no cached row (e.g. OSV never had an entry) rather than returning a null-filled placeholder - a finding with fewer cveDetails entries than cveIds is the correct, honest representation. */
    public Map<String, OsvCveDetail> findByIds(List<String> cveIds) {
        if (cveIds.isEmpty()) {
            return Map.of();
        }
        String placeholders = String.join(",", cveIds.stream().map(id -> "?").toList());
        List<OsvCveDetail> rows = jdbc.query(
                "SELECT cve_id, description, severity, published_date FROM cve_details WHERE cve_id IN (" + placeholders + ") AND description IS NOT NULL",
                (rs, rowNum) -> new OsvCveDetail(
                        rs.getString("cve_id"),
                        rs.getString("description"),
                        rs.getString("severity"),
                        rs.getTimestamp("published_date") == null ? null : rs.getTimestamp("published_date").toInstant()),
                cveIds.toArray());
        return rows.stream().collect(java.util.stream.Collectors.toMap(OsvCveDetail::cveId, r -> r));
    }
}
