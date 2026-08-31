package org.freedonia.bloodhound.server.mcp;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Reads/revokes directly against oauth2_authorization + oauth2_registered_client (see
 * V40__oauth2_authorization_server.sql) - deliberately NOT oauth2_authorization_consent, which
 * McpAuthorizationServerBeans#authorizationConsentService keeps in-memory only (that table exists
 * in the schema but nothing ever writes to it). oauth2_authorization is the real, JDBC-backed
 * record of who has authorized which client - principal_name is the Bloodhound user's email (see
 * auth.CustomUserDetailsService#loadUserByUsername), joined against users.email to scope this to
 * one org, the same way every other admin query in this app scopes by organization_id.
 */
@Repository
public class McpConnectionRepository {

    private static final String SELECT_SQL = "SELECT DISTINCT ON (a.registered_client_id, a.principal_name) "
            + "a.registered_client_id, rc.client_name, a.principal_name, a.authorized_scopes, "
            + "a.access_token_issued_at, a.authorization_code_issued_at, "
            + "a.access_token_expires_at, a.refresh_token_expires_at "
            + "FROM oauth2_authorization a "
            + "JOIN oauth2_registered_client rc ON rc.id = a.registered_client_id "
            + "JOIN users u ON u.email = a.principal_name "
            + "WHERE u.organization_id = ? "
            + "ORDER BY a.registered_client_id, a.principal_name, "
            + "COALESCE(a.access_token_issued_at, a.authorization_code_issued_at) DESC NULLS LAST";

    private static final RowMapper<McpConnection> ROW_MAPPER = (rs, rowNum) -> {
        Timestamp lastActive = rs.getTimestamp("access_token_issued_at") != null
                ? rs.getTimestamp("access_token_issued_at")
                : rs.getTimestamp("authorization_code_issued_at");
        // Refresh tokens (when granted) long outlive access tokens - that's the more meaningful
        // "how long until this client is forced to fully re-authenticate" number for an admin
        // deciding whether a connection is worth revoking. Falls back to the access token's own
        // expiry for a client that was never issued a refresh token at all.
        Timestamp expiresAt = rs.getTimestamp("refresh_token_expires_at") != null
                ? rs.getTimestamp("refresh_token_expires_at")
                : rs.getTimestamp("access_token_expires_at");
        String scopesCsv = rs.getString("authorized_scopes");
        List<String> scopes =
                scopesCsv == null || scopesCsv.isBlank() ? List.of() : Arrays.asList(scopesCsv.split(","));
        return new McpConnection(
                rs.getString("registered_client_id"),
                rs.getString("client_name"),
                rs.getString("principal_name"),
                scopes,
                lastActive != null ? lastActive.toInstant() : null,
                expiresAt != null ? expiresAt.toInstant() : null);
    };

    private final JdbcTemplate jdbc;

    public McpConnectionRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** One row per (client, user) pair, most-recently-active first. */
    public List<McpConnection> findByOrganization(UUID organizationId) {
        return jdbc.query(SELECT_SQL, ROW_MAPPER, organizationId);
    }

    /**
     * Deletes every oauth2_authorization row for this (client, user) pair - not just the most
     * recent - so an older but still-valid refresh token from an earlier authorization_code
     * exchange for the same pair can't outlive the connection an admin just revoked. Scoped to
     * organizationId via the same users join as findByOrganization, so an admin can never revoke
     * another org's connection by guessing a registeredClientId. Returns the number of rows
     * actually deleted - 0 means nothing matched, which the caller treats as a 404.
     */
    public int revoke(UUID organizationId, String registeredClientId, String principalEmail) {
        return jdbc.update(
                "DELETE FROM oauth2_authorization a USING users u "
                        + "WHERE u.email = a.principal_name AND u.organization_id = ? "
                        + "AND a.registered_client_id = ? AND a.principal_name = ?",
                organizationId,
                registeredClientId,
                principalEmail);
    }
}
