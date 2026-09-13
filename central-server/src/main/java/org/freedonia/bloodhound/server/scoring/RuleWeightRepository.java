package org.freedonia.bloodhound.server.scoring;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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

    /**
     * A product/AppSec review found rules_catalog.enabled existed in the schema and was faithfully
     * returned by GET /api/v1/rules-catalog and rendered on the admin page, but nothing anywhere
     * in the codebase ever actually read it to make a decision - a completely inert field an admin
     * could reasonably assume was a working kill switch. Used by ResultIngestionService to filter
     * a module's reported findings before reconciliation, so a disabled rule's findings are never
     * persisted (and its already-open findings from before it was disabled get resolved on the
     * next scan, the same way any finding not reported by ResultIngestionService anymore does).
     *
     * <p>A later security review found the first version of this fix filtered by the bare global
     * rules_catalog.enabled column with no org scoping - any org's ADMIN toggling a rule affected
     * every tenant's ingestion, not just their own. {@code org_rule_overrides} (see its own
     * migration) is now the effective source of truth per org: a row there for (organizationId,
     * rule_id) overrides the catalog's shipped default; no row means the catalog default applies,
     * same as before this table existed.
     */
    public Set<String> findDisabledRuleIds(UUID organizationId) {
        // Second branch of the UNION: pass-through rule ids (ZAP_ALERT_*/NUCLEI_*) have no
        // catalog row to COALESCE against - an override is the only state they have (V55).
        return Set.copyOf(jdbc.queryForList(
                "SELECT rc.rule_id FROM rules_catalog rc "
                        + "LEFT JOIN org_rule_overrides oro ON oro.rule_id = rc.rule_id AND oro.organization_id = ? "
                        + "WHERE COALESCE(oro.enabled, rc.enabled) = FALSE "
                        + "UNION "
                        + "SELECT oro.rule_id FROM org_rule_overrides oro "
                        + "WHERE oro.organization_id = ? AND oro.enabled = FALSE "
                        + "AND NOT EXISTS (SELECT 1 FROM rules_catalog rc WHERE rc.rule_id = oro.rule_id)",
                String.class,
                organizationId,
                organizationId));
    }
}
