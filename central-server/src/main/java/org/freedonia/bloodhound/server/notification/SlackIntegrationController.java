package org.freedonia.bloodhound.server.notification;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/orgs/{orgId}/slack-integration")
@PreAuthorize("hasRole('ADMIN')")
public class SlackIntegrationController {

    private final SlackIntegrationRepository slackIntegrationRepository;

    public SlackIntegrationController(SlackIntegrationRepository slackIntegrationRepository) {
        this.slackIntegrationRepository = slackIntegrationRepository;
    }

    public record SlackConfigRequest(
            String webhookUrl, boolean enabled, List<String> notificationTypes, boolean ownTargetsOnly) {}

    @GetMapping
    public ResponseEntity<SlackIntegration> get(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        Optional<SlackIntegration> integration = slackIntegrationRepository.findByOrganization(orgId);
        return integration.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.noContent().build());
    }

    @PutMapping
    public SlackIntegration save(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal JwtPrincipal principal,
            @RequestBody SlackConfigRequest request) {
        requireSameOrg(orgId, principal);
        // Enforced here, once, before the URL is ever stored - not inside SlackNotifier
        // (see its Javadoc for why that split matters for testability). Without this, an
        // admin-configurable "webhook URL" is an open server-side-request-to-arbitrary-URL
        // primitive.
        if (!SlackWebhookValidator.isValid(request.webhookUrl())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "webhookUrl must be a genuine https://hooks.slack.com/services/... URL");
        }
        List<String> types = request.notificationTypes() == null ? List.of() : request.notificationTypes();
        for (String type : types) {
            try {
                NotificationType.valueOf(type);
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown notification type: " + type);
            }
        }
        return slackIntegrationRepository.upsert(
                orgId, request.webhookUrl(), request.enabled(), types, request.ownTargetsOnly());
    }

    @DeleteMapping
    public ResponseEntity<Void> delete(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        slackIntegrationRepository.delete(orgId);
        return ResponseEntity.noContent().build();
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
