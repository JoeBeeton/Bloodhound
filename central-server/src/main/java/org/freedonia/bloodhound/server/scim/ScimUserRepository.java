package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * SCIM's own view of `users` (see ScimUserRow). All SCIM-provisioned users
 * get identity_source='SCIM', password_hash null - same seam SAML JIT
 * provisioning already uses.
 */
@Repository
public class ScimUserRepository {

    private static final RowMapper<ScimUserRow> ROW_MAPPER = (rs, rowNum) -> new ScimUserRow(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("email"),
            rs.getString("display_name"),
            "ACTIVE".equals(rs.getString("status")),
            rs.getString("external_id"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant());

    private final JdbcTemplate jdbc;

    public ScimUserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ScimUserRow> findByOrgAndId(UUID organizationId, UUID id) {
        return jdbc.query(
                        "SELECT * FROM users WHERE organization_id = ? AND id = ? AND identity_source = 'SCIM'",
                        ROW_MAPPER,
                        organizationId,
                        id)
                .stream()
                .findFirst();
    }

    /** userName maps to email - RFC 7643's canonical unique-identifier field for this deployment. */
    public Optional<ScimUserRow> findByOrgAndUserName(UUID organizationId, String userName) {
        return jdbc.query(
                        "SELECT * FROM users WHERE organization_id = ? AND email = ? AND identity_source = 'SCIM'",
                        ROW_MAPPER,
                        organizationId,
                        userName)
                .stream()
                .findFirst();
    }

    public long countByOrg(UUID organizationId) {
        Long count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM users WHERE organization_id = ? AND identity_source = 'SCIM'",
                Long.class,
                organizationId);
        return count == null ? 0 : count;
    }

    /** startIndex is 1-indexed per RFC 7644 3.4.2. */
    public List<ScimUserRow> listByOrg(UUID organizationId, int startIndex, int count) {
        return jdbc.query(
                "SELECT * FROM users WHERE organization_id = ? AND identity_source = 'SCIM' "
                        + "ORDER BY created_at OFFSET ? LIMIT ?",
                ROW_MAPPER,
                organizationId,
                Math.max(0, startIndex - 1),
                count);
    }

    public ScimUserRow insert(UUID organizationId, String userName, String displayName, boolean active, String externalId) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, organization_id, email, display_name, identity_source, external_id, role, status) "
                        + "VALUES (?, ?, ?, ?, 'SCIM', ?, 'VIEWER', ?)",
                id,
                organizationId,
                userName,
                displayName,
                externalId,
                active ? "ACTIVE" : "DISABLED");
        return findByOrgAndId(organizationId, id).orElseThrow();
    }

    /** PUT-style full replace of the SCIM-managed fields. */
    public void replace(UUID organizationId, UUID id, String userName, String displayName, boolean active, String externalId) {
        jdbc.update(
                "UPDATE users SET email = ?, display_name = ?, status = ?, external_id = ?, updated_at = now() "
                        + "WHERE organization_id = ? AND id = ? AND identity_source = 'SCIM'",
                userName,
                displayName,
                active ? "ACTIVE" : "DISABLED",
                externalId,
                organizationId,
                id);
    }

    public void updateActive(UUID organizationId, UUID id, boolean active) {
        jdbc.update(
                "UPDATE users SET status = ?, updated_at = now() WHERE organization_id = ? AND id = ? AND identity_source = 'SCIM'",
                active ? "ACTIVE" : "DISABLED",
                organizationId,
                id);
    }

    public void updateUserName(UUID organizationId, UUID id, String userName) {
        jdbc.update(
                "UPDATE users SET email = ?, updated_at = now() WHERE organization_id = ? AND id = ? AND identity_source = 'SCIM'",
                userName,
                organizationId,
                id);
    }

    public void updateDisplayName(UUID organizationId, UUID id, String displayName) {
        jdbc.update(
                "UPDATE users SET display_name = ?, updated_at = now() WHERE organization_id = ? AND id = ? AND identity_source = 'SCIM'",
                displayName,
                organizationId,
                id);
    }
}
