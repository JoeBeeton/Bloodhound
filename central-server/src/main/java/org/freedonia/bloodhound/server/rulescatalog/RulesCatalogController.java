package org.freedonia.bloodhound.server.rulescatalog;

import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.access.prepost.PreAuthorize;
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
 * what findings get persisted for the whole organization going forward (see
 * ResultIngestionService, which is what actually enforces enabled - a product/AppSec review found
 * this field previously did nothing at all despite being displayed as though it were live).
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

    private final JdbcTemplate jdbc;

    public RulesCatalogController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/api/v1/rules-catalog")
    public List<RulesCatalogEntry> list() {
        return jdbc.query("SELECT * FROM rules_catalog ORDER BY category, rule_id", ROW_MAPPER);
    }

    public record UpdateRuleEnabledRequest(boolean enabled) {}

    @PatchMapping("/api/v1/rules-catalog/{ruleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public RulesCatalogEntry setEnabled(
            @PathVariable String ruleId, @RequestBody UpdateRuleEnabledRequest request) {
        int rows = jdbc.update("UPDATE rules_catalog SET enabled = ? WHERE rule_id = ?", request.enabled(), ruleId);
        if (rows == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "no such rule");
        }
        return jdbc.queryForObject("SELECT * FROM rules_catalog WHERE rule_id = ?", ROW_MAPPER, ruleId);
    }
}
