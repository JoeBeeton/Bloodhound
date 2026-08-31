package org.freedonia.bloodhound.server.notification;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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
    private final SlackNotifier slackNotifier;
    private final AuditLogRepository auditLogRepository;
    private final String appBaseUrl;

    public SlackIntegrationController(
            SlackIntegrationRepository slackIntegrationRepository,
            SlackNotifier slackNotifier,
            AuditLogRepository auditLogRepository,
            @Value("${bloodhound.notifications.app-base-url}") String appBaseUrl) {
        this.slackIntegrationRepository = slackIntegrationRepository;
        this.slackNotifier = slackNotifier;
        this.auditLogRepository = auditLogRepository;
        this.appBaseUrl = appBaseUrl;
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

    /**
     * A generic 400 body carrying a real, specific message - confirmed live (same finding as
     * UserSelfController#changePassword's own WeakPasswordResponse) that this app's default error
     * handler never exposes a ResponseStatusException's reason text to the caller at all (the JSON
     * body is just {timestamp,status,error,path}, no message field). The three save() validation
     * failures below and test()'s "nothing configured yet" case all previously threw
     * ResponseStatusException with a specific reason - silently swallowed in production, meaning
     * every admin who hit one of these actually saw either a blank error or (worse, since the
     * frontend's res.text() call got back the stringified {timestamp,...} JSON instead of empty)
     * a raw JSON blob, never the intended message.
     */
    public record ErrorMessageResponse(String message) {}

    @PutMapping
    public ResponseEntity<?> save(
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
            Optional<String> existing =
                    slackIntegrationRepository.findByOrganization(orgId).map(SlackIntegration::webhookUrl);
            if (existing.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessageResponse("webhookUrl is required"));
            }
            webhookUrl = existing.get();
        } else if (!SlackWebhookValidator.isValid(webhookUrl)) {
            // Enforced here, once, before the URL is ever stored - not inside SlackNotifier
            // (see its Javadoc for why that split matters for testability). Without this, an
            // admin-configurable "webhook URL" is an open server-side-request-to-arbitrary-URL
            // primitive.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorMessageResponse("webhookUrl must be a genuine https://hooks.slack.com/services/... URL"));
        }
        List<String> types = request.notificationTypes() == null ? List.of() : request.notificationTypes();
        for (String type : types) {
            try {
                NotificationType.valueOf(type);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageResponse("Unknown notification type: " + type));
            }
        }
        SlackIntegration saved =
                slackIntegrationRepository.upsert(orgId, webhookUrl, request.enabled(), types, request.ownTargetsOnly());
        // An audit review found this - configuring where scan/finding alerts get delivered
        // outside the app, and (via the webhookUrl validation above) an SSRF-relevant surface -
        // had no audit trail. Never logs the webhook URL itself, only that one was set and the
        // resulting enabled state, same restraint SlackIntegrationResponse's own masking already
        // applies to every other read of this data.
        auditLogRepository.record(
                orgId,
                principal.userId(),
                principal.email(),
                "SLACK_INTEGRATION_SAVED",
                "ORGANIZATION",
                orgId.toString(),
                "enabled=" + saved.enabled());
        return ResponseEntity.ok(SlackIntegrationResponse.from(saved));
    }

    public record TestSendResponse(boolean success, String detail) {}

    /**
     * A product/ops review found this integration was entirely fire-and-forget: SlackNotifier's
     * real delivery path is deliberately @Async so a slow/unreachable Slack endpoint never delays
     * the scan/finding pipeline, and any failure only ever reached a server log line an admin
     * would have no reason to go looking at. An admin who fat-fingers a webhook URL (or whose
     * webhook gets revoked from the Slack side) currently finds out only when they realize alerts
     * have quietly stopped arriving - potentially never, if alert volume is already low. This
     * fires one real message synchronously and reports the actual outcome back, the same "does
     * this even work" check every other webhook-integration UI (Stripe, GitHub, etc.) offers.
     * Deliberately synchronous, unlike the real delivery path - a manual button click blocking
     * for up to ~8s (SlackNotifier's own HTTP timeout) is the whole point here.
     */
    @PostMapping("/test")
    public ResponseEntity<?> test(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        Optional<SlackIntegration> integration = slackIntegrationRepository.findByOrganization(orgId);
        if (integration.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorMessageResponse("No Slack webhook configured yet - save one first."));
        }
        var result = slackNotifier.attemptDelivery(
                integration.get().webhookUrl(),
                "Bloodhound test notification",
                "This is a test message from Bloodhound. If you're seeing this, delivery is working.",
                "INFO",
                appBaseUrl + "/dashboard");
        return ResponseEntity.ok(new TestSendResponse(result.success(), result.detail()));
    }

    @DeleteMapping
    public ResponseEntity<Void> delete(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        slackIntegrationRepository.delete(orgId);
        auditLogRepository.record(
                orgId, principal.userId(), principal.email(), "SLACK_INTEGRATION_REMOVED", "ORGANIZATION", orgId.toString(), null);
        return ResponseEntity.noContent().build();
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
