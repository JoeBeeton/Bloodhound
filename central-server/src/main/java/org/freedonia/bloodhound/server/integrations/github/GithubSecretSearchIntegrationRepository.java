package org.freedonia.bloodhound.server.integrations.github;

import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.security.SecretCredentialCipher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Same upsert-by-organization_id shape as {@code SlackIntegrationRepository}, but the token is encrypted before it ever reaches the database - see {@link SecretCredentialCipher}. */
@Repository
public class GithubSecretSearchIntegrationRepository {

    private final JdbcTemplate jdbc;
    private final SecretCredentialCipher cipher;

    public GithubSecretSearchIntegrationRepository(JdbcTemplate jdbc, SecretCredentialCipher cipher) {
        this.jdbc = jdbc;
        this.cipher = cipher;
    }

    private GithubSecretSearchIntegration mapRow(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        return new GithubSecretSearchIntegration(
                UUID.fromString(rs.getString("id")),
                UUID.fromString(rs.getString("organization_id")),
                rs.getBytes("encrypted_token"),
                rs.getBoolean("enabled"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant());
    }

    public Optional<GithubSecretSearchIntegration> findByOrganization(UUID organizationId) {
        return jdbc.query(
                        "SELECT * FROM github_secret_search_integrations WHERE organization_id = ?",
                        this::mapRow,
                        organizationId)
                .stream()
                .findFirst();
    }

    /**
     * Used only by the worker-facing internal endpoint ({@code JobController}) that actually
     * needs the plaintext to call GitHub's API - every admin-facing read goes through {@link
     * #findByOrganization}, which never decrypts anything (the controller only ever masks the
     * still-encrypted bytes' existence, not their content).
     */
    public Optional<String> findDecryptedTokenForOrganization(UUID organizationId) {
        return findByOrganization(organizationId)
                .filter(GithubSecretSearchIntegration::enabled)
                .map(i -> decryptBoundToOrganization(organizationId, i.encryptedToken()));
    }

    /** Authenticated with the owning org as GCM associated data - see SecretCredentialCipher#encrypt(String, String). */
    private static String associatedData(UUID organizationId) {
        return "github_secret_search_integrations:" + organizationId;
    }

    /**
     * Rows written before tokens were bound to their org (no associated data) still decrypt the
     * legacy way once, and are immediately re-encrypted bound to this org - so every row is
     * upgraded the first time it's used, with no separate migration step that would need the key.
     */
    private String decryptBoundToOrganization(UUID organizationId, byte[] stored) {
        try {
            return cipher.decrypt(stored, associatedData(organizationId));
        } catch (IllegalStateException boundDecryptFailed) {
            String plaintext = cipher.decrypt(stored);
            jdbc.update(
                    "UPDATE github_secret_search_integrations SET encrypted_token = ? "
                            + "WHERE organization_id = ? AND encrypted_token = ?",
                    cipher.encrypt(plaintext, associatedData(organizationId)),
                    organizationId,
                    stored);
            return plaintext;
        }
    }

    public GithubSecretSearchIntegration upsert(UUID organizationId, String plaintextToken, boolean enabled) {
        byte[] encrypted = cipher.encrypt(plaintextToken, associatedData(organizationId));
        jdbc.update(
                "INSERT INTO github_secret_search_integrations "
                        + "(id, organization_id, encrypted_token, enabled, updated_at) "
                        + "VALUES (?, ?, ?, ?, now()) "
                        + "ON CONFLICT (organization_id) DO UPDATE SET "
                        + "encrypted_token = EXCLUDED.encrypted_token, enabled = EXCLUDED.enabled, updated_at = now()",
                UUID.randomUUID(),
                organizationId,
                encrypted,
                enabled);
        return findByOrganization(organizationId).orElseThrow();
    }

    /**
     * Toggles {@code enabled} without touching {@code encrypted_token} at all - used when an
     * admin only changes the enabled flag (the controller's "blank token = keep existing"
     * path), so that case never has to decrypt-then-re-encrypt the unchanged value just to
     * satisfy an UPDATE statement.
     */
    public void updateEnabledOnly(UUID organizationId, boolean enabled) {
        jdbc.update(
                "UPDATE github_secret_search_integrations SET enabled = ?, updated_at = now() WHERE organization_id = ?",
                enabled,
                organizationId);
    }

    public void delete(UUID organizationId) {
        jdbc.update("DELETE FROM github_secret_search_integrations WHERE organization_id = ?", organizationId);
    }
}
