package org.freedonia.bloodhound.server.rulescatalog;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The catalog itself is read-only to any logged-in user beyond normal authentication - it's
 * in-product documentation (see the /admin/rules-catalog frontend route), not sensitive. Toggling
 * a rule's enabled state is the one write this controller allows, and is ADMIN-only: it changes
 * what findings get persisted going forward (see ResultIngestionService, which is what actually
 * enforces enabled - a product/AppSec review found this field previously did nothing at all
 * despite being displayed as though it were live).
 *
 * <p>A later security review found the first version of this had no organization_id at all - the
 * PATCH endpoint updated the global rules_catalog.enabled column directly, so any org's ADMIN
 * could disable a rule (e.g. TLS_EXPIRED) for every tenant, not just their own. {@code
 * org_rule_overrides} (see its own migration) now holds the per-org effective state; {@code
 * rules_catalog.enabled} is the shipped default every org starts from and is no longer directly
 * writable via this API.
 */
@RestController
public class RulesCatalogController {

    private static final RowMapper<RulesCatalogEntry> ROW_MAPPER = (rs, rowNum) -> new RulesCatalogEntry(
            rs.getString("rule_id"),
            rs.getString("category"),
            rs.getString("default_severity"),
            rs.getString("title"),
            rs.getString("description"),
            rs.getString("remediation_advice"),
            rs.getBigDecimal("weight"),
            rs.getBoolean("enabled"));

    /**
     * COALESCE(oro.enabled, rc.enabled): an org-specific override, if one exists, wins; otherwise
     * the catalog's shipped default applies - same effective-state logic as
     * RuleWeightRepository#findDisabledRuleIds, which is what ResultIngestionService actually
     * enforces at scan time. Kept in exact sync with that query on purpose: this is what the admin
     * page shows, so it must never disagree with what ingestion actually does.
     */
    private static final String SELECT_EFFECTIVE = "SELECT rc.rule_id, rc.category, rc.default_severity, rc.title, "
            + "rc.description, rc.remediation_advice, rc.weight, COALESCE(oro.enabled, rc.enabled) AS enabled "
            + "FROM rules_catalog rc LEFT JOIN org_rule_overrides oro "
            + "ON oro.rule_id = rc.rule_id AND oro.organization_id = ?";

    private final JdbcTemplate jdbc;
    private final AuditLogRepository auditLogRepository;

    public RulesCatalogController(JdbcTemplate jdbc, AuditLogRepository auditLogRepository) {
        this.jdbc = jdbc;
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * Pass-through rules: ZAP_ALERT_<pluginId> / NUCLEI_<templateId> findings carry their rule
     * identity from the scanner and are never seeded into rules_catalog (thousands of them, each
     * self-describing - see ZapAlertMapper). Listed here per org from the rules that org has
     * actually produced findings for, so the same toggle works on them; title/description come
     * from the most recent finding, severity from the most common one, weight is ScoringEngine's
     * default for an unknown id. An override with no matching finding yet (rare: a rule disabled,
     * then every finding of it purged) simply doesn't show until it fires again.
     */
    private static final String SELECT_OBSERVED_PASSTHROUGH = "SELECT f.rule_id, 'WEB_APP' AS category, "
            + "(SELECT severity FROM findings f2 WHERE f2.rule_id = f.rule_id AND f2.target_id = ANY(t.ids) "
            + " GROUP BY severity ORDER BY count(*) DESC LIMIT 1) AS default_severity, "
            + "(SELECT title FROM findings f3 WHERE f3.rule_id = f.rule_id AND f3.target_id = ANY(t.ids) "
            + " ORDER BY created_at DESC LIMIT 1) AS title, "
            + "(SELECT description FROM findings f4 WHERE f4.rule_id = f.rule_id AND f4.target_id = ANY(t.ids) "
            + " ORDER BY created_at DESC LIMIT 1) AS description, "
            + "'Reported by the scanner itself - see the finding''s own reference/solution evidence.' AS remediation_advice, "
            + "1.0 AS weight, COALESCE(oro.enabled, TRUE) AS enabled "
            + "FROM (SELECT array_agg(id) AS ids FROM targets WHERE organization_id = ?) t, "
            + "(SELECT DISTINCT rule_id FROM findings WHERE target_id IN (SELECT id FROM targets WHERE organization_id = ?) "
            + " AND (rule_id LIKE 'ZAP_ALERT_%' OR rule_id LIKE 'NUCLEI_%')) f "
            + "LEFT JOIN org_rule_overrides oro ON oro.rule_id = f.rule_id AND oro.organization_id = ? "
            + "ORDER BY f.rule_id";

    static boolean isPassThroughRuleId(String ruleId) {
        return ruleId != null && (ruleId.startsWith("ZAP_ALERT_") || ruleId.startsWith("NUCLEI_")) && ruleId.length() <= 200;
    }

    @GetMapping("/api/v1/rules-catalog")
    public List<RulesCatalogEntry> list(@AuthenticationPrincipal JwtPrincipal principal) {
        UUID orgId = principal.organizationId();
        List<RulesCatalogEntry> entries =
                new ArrayList<>(jdbc.query(SELECT_EFFECTIVE + " ORDER BY rc.category, rc.rule_id", ROW_MAPPER, orgId));
        entries.addAll(jdbc.query(SELECT_OBSERVED_PASSTHROUGH, ROW_MAPPER, orgId, orgId, orgId));
        return entries;
    }

    public record UpdateRuleEnabledRequest(boolean enabled) {}

    @PatchMapping("/api/v1/orgs/{orgId}/rules-catalog/{ruleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public RulesCatalogEntry setEnabled(
            @PathVariable UUID orgId,
            @PathVariable String ruleId,
            @RequestBody UpdateRuleEnabledRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        Integer ruleExists =
                jdbc.queryForObject("SELECT count(*) FROM rules_catalog WHERE rule_id = ?", Integer.class, ruleId);
        boolean inCatalog = ruleExists != null && ruleExists > 0;
        if (!inCatalog && !isPassThroughRuleId(ruleId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "no such rule");
        }
        jdbc.update(
                "INSERT INTO org_rule_overrides (organization_id, rule_id, enabled) VALUES (?, ?, ?) "
                        + "ON CONFLICT (organization_id, rule_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()",
                orgId,
                ruleId,
                request.enabled());
        auditLogRepository.record(
                orgId,
                principal.userId(),
                principal.email(),
                request.enabled() ? "RULE_ENABLED" : "RULE_DISABLED",
                "RULE",
                ruleId,
                null);
        if (inCatalog) {
            return jdbc.queryForObject(SELECT_EFFECTIVE + " WHERE rc.rule_id = ?", ROW_MAPPER, orgId, ruleId);
        }
        return jdbc.query(SELECT_OBSERVED_PASSTHROUGH, ROW_MAPPER, orgId, orgId, orgId).stream()
                .filter(e -> e.ruleId().equals(ruleId))
                .findFirst()
                .orElse(new RulesCatalogEntry(
                        ruleId, "WEB_APP", "INFO", ruleId, "", "", java.math.BigDecimal.ONE, request.enabled()));
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
