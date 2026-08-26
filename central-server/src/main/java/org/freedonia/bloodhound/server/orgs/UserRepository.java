package org.freedonia.bloodhound.server.orgs;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    private static final RowMapper<User> ROW_MAPPER = (rs, rowNum) -> new User(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("email"),
            rs.getString("display_name"),
            rs.getString("password_hash"),
            rs.getString("identity_source"),
            rs.getString("role"),
            rs.getString("status"),
            rs.getTimestamp("created_at").toInstant());

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public long count() {
        Long count = jdbc.queryForObject("SELECT COUNT(*) FROM users", Long.class);
        return count == null ? 0 : count;
    }

    /**
     * Email is only unique per-organization (see V1__init.sql), not globally.
     * There's no self-serve multi-org signup yet, so more than one match here
     * should never happen in practice - callers treat >1 result as an error
     * rather than silently picking one, until org-scoped login (e.g. an org
     * slug on the login form) is built.
     */
    public List<User> findLocalActiveByEmail(String email) {
        return jdbc.query(
                "SELECT * FROM users WHERE email = ? AND identity_source = 'LOCAL' AND status = 'ACTIVE'",
                ROW_MAPPER,
                email);
    }

    public Optional<User> findById(UUID id) {
        return jdbc.query("SELECT * FROM users WHERE id = ?", ROW_MAPPER, id).stream()
                .findFirst();
    }

    public List<User> findByOrganizationId(UUID organizationId) {
        return jdbc.query(
                "SELECT * FROM users WHERE organization_id = ? ORDER BY created_at", ROW_MAPPER, organizationId);
    }

    public User insertLocalAdmin(UUID organizationId, String email, String displayName, String passwordHash) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, organization_id, email, display_name, password_hash, identity_source, role, status) "
                        + "VALUES (?, ?, ?, ?, ?, 'LOCAL', 'ADMIN', 'ACTIVE')",
                id,
                organizationId,
                email,
                displayName,
                passwordHash);
        return findById(id).orElseThrow();
    }

    /** Admin-created local user (any role) - see OrgUserController#create. Always starts ACTIVE. */
    public User insertLocalUser(UUID organizationId, String email, String displayName, String role, String passwordHash) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, organization_id, email, display_name, password_hash, identity_source, role, status) "
                        + "VALUES (?, ?, ?, ?, ?, 'LOCAL', ?, 'ACTIVE')",
                id,
                organizationId,
                email,
                displayName,
                passwordHash,
                role);
        return findById(id).orElseThrow();
    }

    public void updateRoleAndStatus(UUID id, String role, String status) {
        jdbc.update("UPDATE users SET role = ?, status = ?, updated_at = now() WHERE id = ?", role, status, id);
    }

    public void updatePasswordHash(UUID id, String passwordHash) {
        jdbc.update("UPDATE users SET password_hash = ?, updated_at = now() WHERE id = ?", passwordHash, id);
    }

    public void touchLastLogin(UUID id) {
        jdbc.update("UPDATE users SET last_login_at = now() WHERE id = ?", id);
    }

    public Optional<User> findByOrgIdentitySourceExternalId(UUID organizationId, String identitySource, String externalId) {
        return jdbc.query(
                        "SELECT * FROM users WHERE organization_id = ? AND identity_source = ? AND external_id = ?",
                        ROW_MAPPER,
                        organizationId,
                        identitySource,
                        externalId)
                .stream()
                .findFirst();
    }

    /**
     * JIT provisioning for a SAML-authenticated user: find-or-create keyed on
     * (org, identity_source, external_id) - the same unique key V1__init.sql
     * already reserved for this. password_hash stays null. Starts VIEWER;
     * an admin promotes via the existing role-management endpoints, same as
     * any other new user. Email/display name are re-synced on every login in
     * case the IdP-side profile changed.
     */
    public User findOrCreateSamlUser(UUID organizationId, String externalId, String email, String displayName) {
        Optional<User> existing = findByOrgIdentitySourceExternalId(organizationId, "SAML", externalId);
        if (existing.isPresent()) {
            jdbc.update(
                    "UPDATE users SET email = ?, display_name = ?, updated_at = now() WHERE id = ?",
                    email,
                    displayName,
                    existing.get().id());
            return findById(existing.get().id()).orElseThrow();
        }
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, organization_id, email, display_name, identity_source, external_id, role, status) "
                        + "VALUES (?, ?, ?, ?, 'SAML', ?, 'VIEWER', 'ACTIVE')",
                id,
                organizationId,
                email,
                displayName,
                externalId);
        return findById(id).orElseThrow();
    }
}
