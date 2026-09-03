package org.freedonia.bloodhound.server.rulescatalog;

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

    @GetMapping("/api/v1/rules-catalog")
    public List<RulesCatalogEntry> list(@AuthenticationPrincipal JwtPrincipal principal) {
        return jdbc.query(
                SELECT_EFFECTIVE + " ORDER BY rc.category, rc.rule_id", ROW_MAPPER, principal.organizationId());
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
        if (ruleExists == null || ruleExists == 0) {
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
        return jdbc.queryForObject(SELECT_EFFECTIVE + " WHERE rc.rule_id = ?", ROW_MAPPER, orgId, ruleId);
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
