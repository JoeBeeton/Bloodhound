package org.freedonia.bloodhound.server.orgs;

import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class OrganizationRepository {

    private static final RowMapper<Organization> ROW_MAPPER = (rs, rowNum) -> new Organization(
            UUID.fromString(rs.getString("id")),
            rs.getString("name"),
            rs.getString("slug"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getBoolean("mcp_enabled"));

    private final JdbcTemplate jdbc;

    public OrganizationRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Organization> findBySlug(String slug) {
        return jdbc.query("SELECT * FROM organizations WHERE slug = ?", ROW_MAPPER, slug).stream()
                .findFirst();
    }

    public Optional<Organization> findById(UUID id) {
        return jdbc.query("SELECT * FROM organizations WHERE id = ?", ROW_MAPPER, id).stream()
                .findFirst();
    }

    public Organization insert(String name, String slug) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)", id, name, slug);
        return findById(id).orElseThrow();
    }

    /** Org-wide MCP kill switch - see Organization#mcpEnabled and McpAccessGuard. */
    public void setMcpEnabled(UUID id, boolean enabled) {
        jdbc.update("UPDATE organizations SET mcp_enabled = ? WHERE id = ?", enabled, id);
    }
}
