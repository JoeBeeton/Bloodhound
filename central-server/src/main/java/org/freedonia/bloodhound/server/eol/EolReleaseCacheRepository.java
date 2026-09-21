package org.freedonia.bloodhound.server.eol;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Shared-across-all-targets cache of endoflife.date release-cycle data, keyed by product
 * (not product+version like {@code vuln.CveLookupCacheRepository}) - one API call per
 * product returns every release cycle at once, so there's no per-version cache row to
 * key on the way NVD's per-version lookup needs.
 *
 * <p>{@code eol_product_fetch_state} tracks "have we asked endoflife.date about this
 * product recently" independently of {@code eol_release_cache}'s actual row count: a
 * product whose fetch legitimately came back empty (a 404 - slug no longer in their
 * catalog) would otherwise look identical to "never fetched" under a
 * rows-exist-and-are-fresh check, and get re-queried every single tick forever instead
 * of respecting the stale-after window.
 */
@Repository
public class EolReleaseCacheRepository {

    private final JdbcTemplate jdbc;

    public EolReleaseCacheRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Distinct fingerprinted technology names (restricted to {@code knownTechnologyNames}) whose endoflife.date data hasn't been fetched within {@code staleAfter} - capped at {@code limit} per tick. */
    public List<String> findPendingProducts(java.util.Set<String> knownTechnologyNames, Duration staleAfter, int limit) {
        if (knownTechnologyNames.isEmpty()) {
            return List.of();
        }
        String placeholders = String.join(",", knownTechnologyNames.stream().map(n -> "?").toList());
        return jdbc.query(
                """
                SELECT DISTINCT tech->>'name' AS technology_name
                FROM fingerprints, jsonb_array_elements(technologies) AS tech
                WHERE tech->>'name' IN (%s)
                  AND NOT EXISTS (
                      SELECT 1 FROM eol_product_fetch_state s
                      WHERE s.technology_name = tech->>'name' AND s.fetched_at > now() - (?::interval)
                  )
                LIMIT ?
                """
                        .formatted(placeholders),
                (rs, rowNum) -> rs.getString("technology_name"),
                concatArgs(knownTechnologyNames, staleAfter.toSeconds() + " seconds", limit));
    }

    /** Replaces every cached release cycle for one product wholesale (small per-product row count, same reasoning as {@code vuln.KevCatalogRepository.replaceAll}) and records the fetch attempt - called for both a real result and a legitimate empty one (e.g. a 404), so either way this product won't be re-selected by {@link #findPendingProducts} until it's actually stale again. */
    @Transactional
    public void replaceForProduct(String technologyName, List<EolRelease> releases) {
        jdbc.update("DELETE FROM eol_release_cache WHERE technology_name = ?", technologyName);
        if (!releases.isEmpty()) {
            jdbc.batchUpdate(
                    """
                    INSERT INTO eol_release_cache
                        (technology_name, release_cycle, is_eol, eol_from, is_maintained, latest_version_in_cycle)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    releases,
                    releases.size(),
                    (ps, r) -> {
                        ps.setString(1, technologyName);
                        ps.setString(2, r.releaseCycle());
                        ps.setBoolean(3, r.isEol());
                        ps.setDate(4, r.eolFrom() == null ? null : Date.valueOf(r.eolFrom()));
                        ps.setBoolean(5, r.isMaintained());
                        ps.setString(6, r.latestVersionInCycle());
                    });
        }
        jdbc.update(
                """
                INSERT INTO eol_product_fetch_state (technology_name, fetched_at) VALUES (?, now())
                ON CONFLICT (technology_name) DO UPDATE SET fetched_at = now()
                """,
                technologyName);
    }

    /** Every cached release cycle for every product, grouped by technology name - the input to {@link EolVersionMatcher}, read once per scheduler tick rather than once per candidate. */
    public Map<String, List<EolRelease>> findAllReleases() {
        Map<String, List<EolRelease>> result = new LinkedHashMap<>();
        jdbc.query(
                "SELECT technology_name, release_cycle, is_eol, eol_from, is_maintained, latest_version_in_cycle FROM eol_release_cache",
                rs -> {
                    while (rs.next()) {
                        String technologyName = rs.getString("technology_name");
                        Date eolFrom = rs.getDate("eol_from");
                        result.computeIfAbsent(technologyName, k -> new java.util.ArrayList<>())
                                .add(new EolRelease(
                                        rs.getString("release_cycle"),
                                        rs.getBoolean("is_eol"),
                                        eolFrom == null ? null : eolFrom.toLocalDate(),
                                        rs.getBoolean("is_maintained"),
                                        rs.getString("latest_version_in_cycle")));
                    }
                    return null;
                });
        return result;
    }

    /** When each product's cache was last fetched - one row per product, used as the finding-synthesis watermark the same way {@code vuln.CveLookupCacheRepository.maxCheckedAtByTarget} uses {@code checked_at}. */
    public Map<String, Instant> fetchedAtByProduct() {
        Map<String, Instant> result = new LinkedHashMap<>();
        jdbc.query(
                "SELECT technology_name, fetched_at FROM eol_product_fetch_state",
                rs -> {
                    while (rs.next()) {
                        result.put(rs.getString("technology_name"), rs.getTimestamp("fetched_at").toInstant());
                    }
                    return null;
                });
        return result;
    }

    /** Every currently-fingerprinted (target, hostname, technology, version) where technology is one of {@code knownTechnologyNames} and a version was actually extracted - the direct input to matching, same {@code fingerprints, jsonb_array_elements(technologies)} query shape as {@code vuln.CveLookupCacheRepository.findPendingPairs}, minus the cache-freshness join (matching happens in Java, not SQL, since prefix-matching isn't a plain equality join). */
    public List<EolCandidate> findEolCandidates(java.util.Set<String> knownTechnologyNames) {
        if (knownTechnologyNames.isEmpty()) {
            return List.of();
        }
        String placeholders = String.join(",", knownTechnologyNames.stream().map(n -> "?").toList());
        return jdbc.query(
                """
                SELECT DISTINCT f.target_id, f.hostname, tech->>'name' AS technology_name, tech->>'version' AS version
                FROM fingerprints f
                CROSS JOIN jsonb_array_elements(f.technologies) AS tech
                JOIN targets t ON t.id = f.target_id
                WHERE tech->>'name' IN (%s)
                  AND tech->>'version' IS NOT NULL AND tech->>'version' != ''
                  AND t.is_active = true
                """
                        .formatted(placeholders),
                (rs, rowNum) -> new EolCandidate(
                        java.util.UUID.fromString(rs.getString("target_id")),
                        rs.getString("hostname"),
                        rs.getString("technology_name"),
                        rs.getString("version")),
                knownTechnologyNames.toArray());
    }

    private static Object[] concatArgs(java.util.Set<String> names, Object... rest) {
        Object[] args = new Object[names.size() + rest.length];
        int i = 0;
        for (String n : names) {
            args[i++] = n;
        }
        System.arraycopy(rest, 0, args, i, rest.length);
        return args;
    }
}
