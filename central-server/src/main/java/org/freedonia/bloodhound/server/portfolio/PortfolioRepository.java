package org.freedonia.bloodhound.server.portfolio;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class PortfolioRepository {

    private static final RowMapper<Portfolio> ROW_MAPPER = (rs, rowNum) -> new Portfolio(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("name"),
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public PortfolioRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Portfolio insert(UUID organizationId, String name) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO portfolios (id, organization_id, name) VALUES (?, ?, ?)", id, organizationId, name);
        return findById(id).orElseThrow();
    }

    public Optional<Portfolio> findById(UUID id) {
        return jdbc.query("SELECT * FROM portfolios WHERE id = ?", ROW_MAPPER, id).stream().findFirst();
    }

    public Optional<Portfolio> findByIdAndOrganization(UUID id, UUID organizationId) {
        return jdbc.query("SELECT * FROM portfolios WHERE id = ? AND organization_id = ?", ROW_MAPPER, id, organizationId)
                .stream()
                .findFirst();
    }

    public List<Portfolio> findByOrganization(UUID organizationId) {
        return jdbc.query(
                "SELECT * FROM portfolios WHERE organization_id = ? ORDER BY name ASC", ROW_MAPPER, organizationId);
    }

    /** Member targets are never deleted - the FK's ON DELETE SET NULL un-groups them at the DB level, nothing else needed here. */
    public void delete(UUID id) {
        jdbc.update("DELETE FROM portfolios WHERE id = ?", id);
    }
}
