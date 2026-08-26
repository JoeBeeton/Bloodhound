package org.freedonia.bloodhound.server.notification;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Always scoped to the authenticated user's own organization - no org id in the path, unlike the admin-facing SCIM/SSO/Slack config endpoints. */
@RestController
@RequestMapping("/api/v1/notifications")
public class NotificationController {

    private final NotificationRepository notificationRepository;

    public NotificationController(NotificationRepository notificationRepository) {
        this.notificationRepository = notificationRepository;
    }

    public record NotificationsResponse(List<Notification> notifications, int unreadCount) {}

    @GetMapping
    public NotificationsResponse list(
            @AuthenticationPrincipal JwtPrincipal principal,
            @RequestParam(defaultValue = "false") boolean unreadOnly,
            @RequestParam(defaultValue = "30") int limit) {
        List<Notification> notifications =
                notificationRepository.findByOrganization(principal.organizationId(), unreadOnly, Math.min(limit, 100));
        int unreadCount = notificationRepository.countUnread(principal.organizationId());
        return new NotificationsResponse(notifications, unreadCount);
    }

    @PatchMapping("/{id}/read")
    public ResponseEntity<Void> markRead(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        notificationRepository.markRead(principal.organizationId(), id);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/mark-all-read")
    public ResponseEntity<Void> markAllRead(@AuthenticationPrincipal JwtPrincipal principal) {
        notificationRepository.markAllRead(principal.organizationId());
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
