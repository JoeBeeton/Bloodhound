package org.freedonia.bloodhound.server.botnet;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** A full local mirror of Feodo Tracker's "online" IP list - small (a handful of entries in practice, confirmed live), same wholesale-replace shape as {@code vuln.KevCatalogRepository}. */
@Repository
public class BotnetIpCacheRepository {

    private final JdbcTemplate jdbc;

    public BotnetIpCacheRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean isStale(Duration maxAge) {
        Timestamp newestFetch = jdbc.queryForObject("SELECT MAX(fetched_at) FROM botnet_ip_cache_meta", Timestamp.class);
        return newestFetch == null || newestFetch.toInstant().isBefore(Instant.now().minus(maxAge));
    }

    /** The single "last fetched at" watermark - see botnet_ip_cache_meta's own migration comment on why this is tracked separately from the cache rows themselves (a legitimately-empty feed must still count as "freshly checked"). */
    public Instant fetchedAt() {
        Timestamp ts = jdbc.queryForObject("SELECT MAX(fetched_at) FROM botnet_ip_cache_meta", Timestamp.class);
        return ts == null ? null : ts.toInstant();
    }

    @Transactional
    public void replaceAll(List<BotnetIpEntry> entries) {
        jdbc.update("DELETE FROM botnet_ip_cache");
        if (!entries.isEmpty()) {
            jdbc.batchUpdate(
                    "INSERT INTO botnet_ip_cache (ip_address, malware, first_seen) VALUES (?, ?, ?)",
                    entries,
                    entries.size(),
                    (ps, entry) -> {
                        ps.setString(1, entry.ipAddress());
                        ps.setString(2, entry.malware());
                        ps.setDate(3, entry.firstSeen() == null ? null : Date.valueOf(entry.firstSeen()));
                    });
        }
        jdbc.update("INSERT INTO botnet_ip_cache_meta (id, fetched_at) VALUES (1, now()) "
                + "ON CONFLICT (id) DO UPDATE SET fetched_at = now()");
    }

    /** The subset of the given IP addresses currently listed as an active botnet C2, keyed by IP. */
    public Map<String, BotnetIpEntry> findMatching(Set<String> ipAddresses) {
        if (ipAddresses.isEmpty()) {
            return Map.of();
        }
        String placeholders = String.join(",", ipAddresses.stream().map(ip -> "?").toList());
        Map<String, BotnetIpEntry> result = new LinkedHashMap<>();
        jdbc.query(
                "SELECT ip_address, malware, first_seen FROM botnet_ip_cache WHERE ip_address IN (" + placeholders + ")",
                rs -> {
                    while (rs.next()) {
                        Date firstSeen = rs.getDate("first_seen");
                        result.put(
                                rs.getString("ip_address"),
                                new BotnetIpEntry(
                                        rs.getString("ip_address"), rs.getString("malware"),
                                        firstSeen == null ? null : firstSeen.toLocalDate()));
                    }
                    return null;
                },
                ipAddresses.toArray());
        return result;
    }
}
