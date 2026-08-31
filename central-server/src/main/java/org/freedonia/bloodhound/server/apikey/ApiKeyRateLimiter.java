package org.freedonia.bloodhound.server.apikey;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * A security review found ApiKeyAuthFilter had no rate limiting at all - once authenticated, a
 * caller could hit any allowlisted GET/export endpoint at unlimited request rate. ROLE_API_KEY is
 * already GET-only against an allowlist (see ApiKeyAuthFilter's own javadoc), so this was never a
 * write/data-integrity risk, but a leaked or malicious key could still drive unbounded read/CSV-
 * export load against the shared database - real infrastructure cost affecting every other org's
 * queries on the same central-server, not just the key owner's own org.
 *
 * <p>Keyed by the API key's own row id, not by IP or org - unlike LoginAttemptLimiter (no
 * identity exists yet at login time, so email is the best available key) or DcrRateLimiter (no
 * identity at all pre-registration, so IP is the best available key), a validated API key call
 * already has the strongest possible identity available: the specific key that was presented.
 * Generous relative to LoginAttemptLimiter/DcrRateLimiter's own thresholds - those guard rare,
 * human-paced actions (a login attempt, a one-time client registration); this guards a
 * legitimate integration's normal polling/export traffic, which can reasonably run at several
 * requests per second in bursts.
 */
@Component
public class ApiKeyRateLimiter {

    private static final int MAX_REQUESTS = 120;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final ConcurrentHashMap<UUID, Window> byKeyId = new ConcurrentHashMap<>();

    public void checkAllowed(UUID apiKeyId) {
        Window window = byKeyId.get(apiKeyId);
        if (window != null && window.isLimited()) {
            throw new ApiKeyRateLimitedException(window.remainingLockoutSeconds());
        }
    }

    public void recordRequest(UUID apiKeyId) {
        byKeyId.compute(apiKeyId, (k, existing) -> {
            Window window = existing != null && !existing.windowExpired() ? existing : new Window();
            window.count++;
            window.windowStart = window.windowStart == null ? Instant.now() : window.windowStart;
            return window;
        });
    }

    /**
     * Same unbounded-map-growth concern LoginAttemptLimiter/DcrRateLimiter's own eviction sweeps
     * document - bounds this map to roughly "API keys actually used in the last window", not
     * every key ever created.
     */
    @Scheduled(fixedRate = 15, initialDelay = 15, timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    void evictExpiredEntries() {
        byKeyId.values().removeIf(Window::windowExpired);
    }

    static final class ApiKeyRateLimitedException extends RuntimeException {
        private final long retryAfterSeconds;

        ApiKeyRateLimitedException(long retryAfterSeconds) {
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
