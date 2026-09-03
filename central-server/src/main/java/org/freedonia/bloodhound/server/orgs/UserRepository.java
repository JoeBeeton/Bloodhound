package org.freedonia.bloodhound.server.orgs;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

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
            rs.getTimestamp("created_at").toInstant(),
            rs.getBoolean("mcp_enabled"),
            rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toInstant() : null);

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

    /**
     * Enforces "at least one active admin must remain in the organization" - a security review
     * found the controller had no such invariant at all: two different ADMINs demoting each
     * other in the same instant could both succeed, since neither is a "change your own role"
     * self-demotion (already blocked elsewhere), orphaning the org with zero admins and no one
     * left who could promote anyone back without direct DB access.
     *
     * <p>{@code SELECT ... FOR UPDATE} on every currently-active-admin row in the org, not a
     * single UPDATE with an EXISTS-guarded WHERE clause: an EXISTS check evaluated as part of
     * the UPDATE's own WHERE clause was tried first and looked atomic, but a live concurrent
     * test (two real HTTP requests firing the mutual-demotion race simultaneously) proved it
     * insufficient - both statements' EXISTS subqueries ran against snapshots taken before
     * either had committed, so each saw the other admin as still active and both succeeded,
     * leaving zero admins. This is the textbook Postgres write-skew anomaly, and the actual fix
     * for it is locking: {@code FOR UPDATE} here forces a second concurrent call for the same
     * org to block until this transaction commits, so by the time it proceeds it sees this
     * call's already-committed result, not a stale snapshot - re-verified with the same live
     * concurrent test after this change, zero admins left in either run.
     *
     * @return true if the row was actually updated, false if it was rejected because it would
     *     have left the organization with no active admin
     */
    @Transactional
    public boolean updateRoleAndStatus(UUID id, String role, String status) {
        List<UUID> lockedActiveAdminIds = jdbc.query(
                """
                SELECT u2.id FROM users u2
                WHERE u2.organization_id = (SELECT organization_id FROM users WHERE id = ?)
                  AND u2.role = 'ADMIN' AND u2.status = 'ACTIVE'
                FOR UPDATE
                """,
                (rs, rowNum) -> UUID.fromString(rs.getString("id")),
                id);

        boolean targetCurrentlyActiveAdmin = lockedActiveAdminIds.contains(id);
        boolean targetRemainsActiveAdmin = "ADMIN".equals(role) && "ACTIVE".equals(status);
        boolean wouldOrphanOrg = targetCurrentlyActiveAdmin && !targetRemainsActiveAdmin && lockedActiveAdminIds.size() <= 1;
        if (wouldOrphanOrg) {
            return false;
        }

        int updated = jdbc.update("UPDATE users SET role = ?, status = ?, updated_at = now() WHERE id = ?", role, status, id);
        return updated > 0;
    }

    public void updatePasswordHash(UUID id, String passwordHash) {
        jdbc.update("UPDATE users SET password_hash = ?, updated_at = now() WHERE id = ?", passwordHash, id);
    }

    public void touchLastLogin(UUID id) {
        jdbc.update("UPDATE users SET last_login_at = now() WHERE id = ?", id);
    }

    /** Per-user MCP kill switch - see User#mcpEnabled and McpAccessGuard. */
    public void setMcpEnabled(UUID id, boolean enabled) {
        jdbc.update("UPDATE users SET mcp_enabled = ?, updated_at = now() WHERE id = ?", enabled, id);
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

    /** See findOrCreateSamlUser's own javadoc for why this fallback exists. */
    private Optional<User> findByOrgIdentitySourceEmail(UUID organizationId, String identitySource, String email) {
        return jdbc.query(
                        "SELECT * FROM users WHERE organization_id = ? AND identity_source = ? AND email = ?",
                        ROW_MAPPER,
                        organizationId,
                        identitySource,
                        email)
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
     *
     * <p>A security/reliability review found the external_id lookup alone always missed for any
     * IdP issuing a *transient* NameID - SAML's own spec-recommended default for privacy, a
     * fresh, deliberately unlinkable identifier on every single login (confirmed live against
     * this app's own bundled test IdP, which defaults to exactly that format). external_id
     * differs on every login for such an IdP, so this always took the "not found" branch past the
     * very first login ever, and the INSERT below then permanently 500'd on
     * uq_users_org_email for every subsequent login by the same real person. Falling back to a
     * lookup by email (same org + identity_source trust boundary the external_id lookup already
     * had) finds that already-provisioned account and re-links it to whatever new transient id
     * this login carries, instead of trying to create a second, colliding row for them.
     */
    public User findOrCreateSamlUser(UUID organizationId, String externalId, String email, String displayName) {
        Optional<User> existing = findByOrgIdentitySourceExternalId(organizationId, "SAML", externalId);
        if (existing.isEmpty()) {
            existing = findByOrgIdentitySourceEmail(organizationId, "SAML", email);
        }
        if (existing.isPresent()) {
            jdbc.update(
                    "UPDATE users SET email = ?, display_name = ?, external_id = ?, updated_at = now() WHERE id = ?",
                    email,
                    displayName,
                    externalId,
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
