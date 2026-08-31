package org.freedonia.bloodhound.server.target;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * A security review found TargetController#createBulk had no limit on how often it could be
 * called, unlike the bearer-token paths (apikey.ApiKeyRateLimiter, scim.ScimTokenRateLimiter)
 * this session already hardened. This one is reached via a regular logged-in session rather than
 * a leaked static credential, but the underlying risk is the same shape: each call runs a real
 * synchronous DNS lookup per hostname (SafeAddressValidator#requireSafeIfResolvable, up to 100 per
 * request per BulkCreateTargetsRequest's own cap) - with no limit on repeated calls, a
 * compromised or malicious session could drive unbounded outbound DNS traffic at zero cost to
 * itself. The per-org target cap bounds how many targets actually get *persisted*, but does
 * nothing to bound the DNS-lookup cost of repeatedly submitting batches that mostly fail it.
 *
 * <p>Keyed by user id, not by API-key/token row id like its two siblings - a JWT session's
 * strongest available identity is the authenticated user, the same reasoning
 * UserSelfController#changePassword's own LoginAttemptLimiter reuse (keyed by email, the
 * strongest identity available there) already established for a JWT-session-scoped guard. Far
 * tighter than ApiKeyRateLimiter/ScimTokenRateLimiter's 120/min: those guard normal integration
 * polling traffic, this guards an occasional, human-paced bulk-onboarding action - even a
 * generous real user would rarely call this more than a handful of times in one sitting.
 */
@Component
public class TargetBulkCreateRateLimiter {

    private static final int MAX_REQUESTS = 10;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final ConcurrentHashMap<UUID, Window> byUserId = new ConcurrentHashMap<>();

    public void checkAllowed(UUID userId) {
        Window window = byUserId.get(userId);
        if (window != null && window.isLimited()) {
            throw new TargetBulkCreateRateLimitedException(window.remainingLockoutSeconds());
        }
    }

    public void recordRequest(UUID userId) {
        byUserId.compute(userId, (k, existing) -> {
            Window window = existing != null && !existing.windowExpired() ? existing : new Window();
            window.count++;
            window.windowStart = window.windowStart == null ? Instant.now() : window.windowStart;
            return window;
        });
    }

    /** Same unbounded-map-growth concern ApiKeyRateLimiter/ScimTokenRateLimiter's own eviction sweeps document. */
    @Scheduled(fixedRate = 15, initialDelay = 15, timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    void evictExpiredEntries() {
        byUserId.values().removeIf(Window::windowExpired);
    }

    static final class TargetBulkCreateRateLimitedException extends RuntimeException {
        private final long retryAfterSeconds;

        TargetBulkCreateRateLimitedException(long retryAfterSeconds) {
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
