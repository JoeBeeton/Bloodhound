package org.freedonia.bloodhound.server.scim;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * A security review found ScimTokenAuthFilter had no rate limiting at all, unlike
 * apikey.ApiKeyAuthFilter's own ApiKeyRateLimiter (added earlier this session for exactly this
 * class of endpoint). This gap actually matters more, not less: ROLE_SCIM has real WRITE access
 * (provisioning/deprovisioning users - see ScimUsersController), while ROLE_API_KEY is strictly
 * GET-only against an allowlist. A leaked or malicious SCIM token could previously drive unlimited
 * user-lifecycle writes at unlimited request rate.
 *
 * <p>Same shape as ApiKeyRateLimiter, including its 120/min threshold - see that class's own
 * javadoc for why a validated bearer credential is keyed by its own row id rather than by IP/org,
 * and why the threshold is generous relative to LoginAttemptLimiter/DcrRateLimiter's own (this
 * guards a legitimate IdP's normal provisioning sync traffic, not a rare human-paced action). A
 * real IdP sync is typically much lower-frequency than this, but a bulk initial
 * reconciliation/onboarding could legitimately burst - no evidence this needs a materially
 * different number than the already-proven API-key threshold, so it isn't invented one.
 */
@Component
public class ScimTokenRateLimiter {

    private static final int MAX_REQUESTS = 120;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final ConcurrentHashMap<UUID, Window> byTokenId = new ConcurrentHashMap<>();

    public void checkAllowed(UUID scimTokenId) {
        Window window = byTokenId.get(scimTokenId);
        if (window != null && window.isLimited()) {
            throw new ScimTokenRateLimitedException(window.remainingLockoutSeconds());
        }
    }

    public void recordRequest(UUID scimTokenId) {
        byTokenId.compute(scimTokenId, (k, existing) -> {
            Window window = existing != null && !existing.windowExpired() ? existing : new Window();
            window.count++;
            window.windowStart = window.windowStart == null ? Instant.now() : window.windowStart;
            return window;
        });
    }

    /** Same unbounded-map-growth concern ApiKeyRateLimiter's own eviction sweep documents. */
    @Scheduled(fixedRate = 15, initialDelay = 15, timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    void evictExpiredEntries() {
        byTokenId.values().removeIf(Window::windowExpired);
    }

    static final class ScimTokenRateLimitedException extends RuntimeException {
        private final long retryAfterSeconds;

        ScimTokenRateLimitedException(long retryAfterSeconds) {
            this.retryAfterSeconds = retryAfterSeconds;
        }

        long retryAfterSeconds() {
            return retryAfterSeconds;
        }
    }

    private static final class Window {
        int count = 0;
        Instant windowStart;

        boolean windowExpired() {
            return windowStart != null && Instant.now().isAfter(windowStart.plus(WINDOW));
        }

        boolean isLimited() {
            return !windowExpired() && count >= MAX_REQUESTS;
        }

        long remainingLockoutSeconds() {
            if (!isLimited()) {
                return 0;
            }
            Duration remaining = Duration.between(Instant.now(), windowStart.plus(WINDOW));
            return Math.max(0, remaining.toSeconds());
        }
    }
}
