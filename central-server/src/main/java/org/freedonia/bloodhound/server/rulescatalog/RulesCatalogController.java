package org.freedonia.bloodhound.server.rulescatalog;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only view of every check Bloodhound runs - doubles as in-product
 * documentation (see the /admin/rules-catalog frontend route), so no
 * restriction beyond normal authentication: any logged-in user can see what
 * the platform checks for, this isn't sensitive.
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
}
