package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** rule_id -> weight, straight from rules_catalog. ScoringEngine defaults to 1.0 for any rule_id not present here. */
@Repository
public class RuleWeightRepository {

    private final JdbcTemplate jdbc;

    public RuleWeightRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, BigDecimal> findAllWeights() {
        return jdbc.query(
                        "SELECT rule_id, weight FROM rules_catalog",
                        (rs, rowNum) -> Map.entry(rs.getString("rule_id"), rs.getBigDecimal("weight")))
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * rule_ids that can ONLY ever be produced by a Tier 2 (deep scan) module - e.g.
     * NETWORK_ANONYMOUS_FTP, NETWORK_FULL_PORT_SURFACE. Deliberately excludes rule_ids a
     * Tier 2 module merely enriches (e.g. PORT_UNEXPECTED_OPEN_ADMIN_SERVICE), since a Tier
     * 1 light scan is equally capable of producing those independently. Used to compute the
     * Tier-1-only "fair comparison" score alongside the full score.
     */
    public Set<String> findTier2ExclusiveRuleIds() {
        return Set.copyOf(jdbc.queryForList(
                "SELECT rule_id FROM rules_catalog WHERE emitted_by_tier1 = FALSE", String.class));
    }
}
