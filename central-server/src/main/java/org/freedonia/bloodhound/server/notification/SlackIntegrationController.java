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
            /** Null/blank means "keep the currently-stored webhook unchanged" - see #save. Required on first save. */
            String webhookUrl,
            boolean enabled,
            List<String> notificationTypes,
            boolean ownTargetsOnly) {}

    /** Never carries the real webhookUrl - see {@link SlackWebhookValidator#mask}. */
    public record SlackIntegrationResponse(
            UUID id,
            UUID organizationId,
            String webhookUrlMasked,
            boolean enabled,
            List<String> notificationTypes,
            boolean ownTargetsOnly) {
        static SlackIntegrationResponse from(SlackIntegration i) {
            return new SlackIntegrationResponse(
                    i.id(),
                    i.organizationId(),
                    SlackWebhookValidator.mask(i.webhookUrl()),
                    i.enabled(),
                    i.notificationTypes(),
                    i.ownTargetsOnly());
        }
    }

    @GetMapping
    public ResponseEntity<SlackIntegrationResponse> get(
            @PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        Optional<SlackIntegration> integration = slackIntegrationRepository.findByOrganization(orgId);
        return integration
                .map(i -> ResponseEntity.ok(SlackIntegrationResponse.from(i)))
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    @PutMapping
    public SlackIntegrationResponse save(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal JwtPrincipal principal,
            @RequestBody SlackConfigRequest request) {
        requireSameOrg(orgId, principal);
        String webhookUrl = request.webhookUrl();
        if (webhookUrl == null || webhookUrl.isBlank()) {
            // The frontend never has the real URL to re-submit once it's masked (see
            // SlackWebhookValidator#mask's javadoc for why) - a blank field here means "the admin
            // is only changing enabled/notificationTypes/ownTargetsOnly, leave the webhook as-is",
            // not "clear the webhook". That requires an existing row; there's nothing to keep on
            // a first-ever save.
            webhookUrl = slackIntegrationRepository
                    .findByOrganization(orgId)
                    .map(SlackIntegration::webhookUrl)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "webhookUrl is required"));
        } else if (!SlackWebhookValidator.isValid(webhookUrl)) {
            // Enforced here, once, before the URL is ever stored - not inside SlackNotifier
            // (see its Javadoc for why that split matters for testability). Without this, an
            // admin-configurable "webhook URL" is an open server-side-request-to-arbitrary-URL
            // primitive.
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
        SlackIntegration saved =
                slackIntegrationRepository.upsert(orgId, webhookUrl, request.enabled(), types, request.ownTargetsOnly());
        return SlackIntegrationResponse.from(saved);
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
