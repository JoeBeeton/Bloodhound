package org.freedonia.bloodhound.server.auth.sso;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityProviderRepository {

    private static final RowMapper<IdentityProvider> ROW_MAPPER = (rs, rowNum) -> new IdentityProvider(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("organization_id")),
            rs.getString("registration_id"),
            rs.getString("idp_entity_id"),
            rs.getString("idp_sso_url"),
            rs.getString("idp_x509_cert"),
            rs.getString("email_attribute_name"),
            rs.getString("display_name_attribute_name"),
            rs.getBoolean("enabled"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant());

    private final JdbcTemplate jdbc;

    public IdentityProviderRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<IdentityProvider> findByRegistrationId(String registrationId) {
        return jdbc.query("SELECT * FROM identity_providers WHERE registration_id = ?", ROW_MAPPER, registrationId)
                .stream()
                .findFirst();
    }

    public Optional<IdentityProvider> findByOrganizationId(UUID organizationId) {
        return jdbc.query("SELECT * FROM identity_providers WHERE organization_id = ?", ROW_MAPPER, organizationId)
                .stream()
                .findFirst();
    }

    /** All enabled registrations - used at startup-adjacent points where every registration_id must resolve. */
    public List<IdentityProvider> findAllEnabled() {
        return jdbc.query("SELECT * FROM identity_providers WHERE enabled = true", ROW_MAPPER);
    }

    /** Upsert-by-org: an org has at most one IdP config (see V18's UNIQUE(organization_id)). */
    public IdentityProvider upsert(
            UUID organizationId,
            String registrationId,
            String idpEntityId,
            String idpSsoUrl,
            String idpX509Cert,
            String emailAttributeName,
            String displayNameAttributeName,
            boolean enabled) {
        jdbc.update(
                """
                INSERT INTO identity_providers
                    (organization_id, registration_id, idp_entity_id, idp_sso_url, idp_x509_cert,
                     email_attribute_name, display_name_attribute_name, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (organization_id) DO UPDATE SET
                    registration_id = EXCLUDED.registration_id,
                    idp_entity_id = EXCLUDED.idp_entity_id,
                    idp_sso_url = EXCLUDED.idp_sso_url,
                    idp_x509_cert = EXCLUDED.idp_x509_cert,
                    email_attribute_name = EXCLUDED.email_attribute_name,
                    display_name_attribute_name = EXCLUDED.display_name_attribute_name,
                    enabled = EXCLUDED.enabled,
                    updated_at = now()
                """,
                organizationId,
                registrationId,
                idpEntityId,
                idpSsoUrl,
                idpX509Cert,
                emailAttributeName,
                displayNameAttributeName,
                enabled);
        return findByOrganizationId(organizationId).orElseThrow();
    }
}
