package org.freedonia.bloodhound.server.notification;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SlackIntegrationRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public SlackIntegrationRepository(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    private SlackIntegration mapRow(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        List<String> types;
        try {
            types = objectMapper.readValue(rs.getString("notification_types"), new TypeReference<List<String>>() {});
        } catch (Exception e) {
            types = List.of();
        }
        return new SlackIntegration(
                UUID.fromString(rs.getString("id")),
                UUID.fromString(rs.getString("organization_id")),
                rs.getString("webhook_url"),
                rs.getBoolean("enabled"),
                types,
                rs.getBoolean("own_targets_only"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant());
    }

    public Optional<SlackIntegration> findByOrganization(UUID organizationId) {
        return jdbc.query("SELECT * FROM slack_integrations WHERE organization_id = ?", this::mapRow, organizationId)
                .stream()
                .findFirst();
    }

    public SlackIntegration upsert(
            UUID organizationId, String webhookUrl, boolean enabled, List<String> types, boolean ownTargetsOnly) {
        String typesJson;
        try {
            typesJson = objectMapper.writeValueAsString(types);
        } catch (Exception e) {
            typesJson = "[]";
        }
        jdbc.update(
                "INSERT INTO slack_integrations "
                        + "(id, organization_id, webhook_url, enabled, notification_types, own_targets_only, updated_at) "
                        + "VALUES (?, ?, ?, ?, ?::jsonb, ?, now()) "
                        + "ON CONFLICT (organization_id) DO UPDATE SET "
                        + "webhook_url = EXCLUDED.webhook_url, enabled = EXCLUDED.enabled, "
                        + "notification_types = EXCLUDED.notification_types, "
                        + "own_targets_only = EXCLUDED.own_targets_only, updated_at = now()",
                UUID.randomUUID(),
                organizationId,
                webhookUrl,
                enabled,
                typesJson,
                ownTargetsOnly);
        return findByOrganization(organizationId).orElseThrow();
    }

    public void delete(UUID organizationId) {
        jdbc.update("DELETE FROM slack_integrations WHERE organization_id = ?", organizationId);
    }
}
