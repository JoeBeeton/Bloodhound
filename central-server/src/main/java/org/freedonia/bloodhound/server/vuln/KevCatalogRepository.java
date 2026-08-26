package org.freedonia.bloodhound.server.vuln;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** A full local mirror of the CISA KEV catalog - small enough (~1600 rows) to replace wholesale on each refresh rather than diffing. */
@Repository
public class KevCatalogRepository {

    private final JdbcTemplate jdbc;

    public KevCatalogRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean isStale(Duration maxAge) {
        Timestamp newestFetch = jdbc.queryForObject("SELECT MAX(fetched_at) FROM kev_catalog", Timestamp.class);
        return newestFetch == null || newestFetch.toInstant().isBefore(Instant.now().minus(maxAge));
    }

    @Transactional
    public void replaceAll(List<KevEntry> entries) {
        jdbc.update("DELETE FROM kev_catalog");
        jdbc.batchUpdate(
                """
                INSERT INTO kev_catalog (cve_id, vendor_project, product, vulnerability_name, date_added, fetched_at)
                VALUES (?, ?, ?, ?, ?, now())
                """,
                entries,
                entries.size(),
                (ps, entry) -> {
                    ps.setString(1, entry.cveId());
                    ps.setString(2, entry.vendorProject());
                    ps.setString(3, entry.product());
                    ps.setString(4, entry.vulnerabilityName());
                    ps.setDate(5, entry.dateAdded() == null ? null : Date.valueOf(entry.dateAdded()));
                });
    }

    /** The subset of the given CVE IDs that are present in the KEV catalog. */
    public Set<String> findMatching(Set<String> cveIds) {
        if (cveIds.isEmpty()) {
            return Set.of();
        }
        String placeholders = cveIds.stream().map(id -> "?").collect(Collectors.joining(","));
        List<String> matched = jdbc.queryForList(
                "SELECT cve_id FROM kev_catalog WHERE cve_id IN (" + placeholders + ")",
                String.class,
                cveIds.toArray());
        return Set.copyOf(matched);
    }
}
