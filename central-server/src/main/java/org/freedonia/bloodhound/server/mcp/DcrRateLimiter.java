package org.freedonia.bloodhound.server.mcp;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * A security review found POST /oauth2/register (RFC 7591 Dynamic Client Registration, wired via
 * McpAuthorizationServerConfigurer#dynamicClientRegistration in McpSecurityConfig) is - correctly,
 * by design - reachable with zero prior authentication: that's the entire point of DCR, letting a
 * new MCP client (e.g. claude.ai's connector UI) self-register without an admin pre-creating
 * credentials. Confirmed live: a bare unauthenticated POST returns a real client_id/client_secret,
 * with nothing at all bounding how many times one caller can do this. Every registration is a
 * permanent row in oauth2_registered_client - unlimited repeated calls is an unauthenticated,
 * unbounded storage-growth DoS against the shared database, not just a theoretical concern for a
 * self-hosted single-instance deployment with finite disk.
 *
 * <p>IP-keyed, not email-keyed like LoginAttemptLimiter - there's no account identity at all at
 * this pre-auth endpoint. A real client only ever needs to register once (ever, in this app's
 * actual usage - see McpSecurityConfig's own "functional, not styled" first-version scope cut),
 * so this is deliberately tight: legitimate setup traffic is rare and low-volume, unlike a login
 * form real users hit constantly. See McpDcrRateLimitFilter for where this is enforced, and
 * LoginAttemptLimiter's own javadoc for why request.getRemoteAddr() (not a trusted proxy chain -
 * none is configured anywhere in this app) is the honest, if imperfect, identity to key on here.
 */
@Component
public class DcrRateLimiter {

    private static final int MAX_REGISTRATIONS = 5;
    private static final Duration WINDOW = Duration.ofHours(1);

    private final ConcurrentHashMap<String, Attempts> byIp = new ConcurrentHashMap<>();

    public void checkAllowed(String ip) {
        Attempts attempts = byIp.get(key(ip));
        if (attempts != null && attempts.isLimited()) {
            throw new DcrRateLimitedException(attempts.remainingLockoutSeconds());
        }
    }

    public void recordAttempt(String ip) {
        byIp.compute(key(ip), (k, existing) -> {
            Attempts attempts = existing != null && !existing.windowExpired() ? existing : new Attempts();
            attempts.count++;
            attempts.windowStart = attempts.windowStart == null ? Instant.now() : attempts.windowStart;
            return attempts;
        });
    }

    /**
     * Same unbounded-map-growth concern LoginAttemptLimiter's own eviction sweep documents - many
     * distinct real source IPs (a botnet, a pool of open proxies) is a realistic way to grow this
     * map without bound otherwise.
     */
    @Scheduled(fixedRate = 15, initialDelay = 15, timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    void evictExpiredEntries() {
        byIp.values().removeIf(Attempts::windowExpired);
    }

    private static String key(String ip) {
        return ip == null ? "" : ip;
    }

    static final class DcrRateLimitedException extends RuntimeException {
        private final long retryAfterSeconds;

        DcrRateLimitedException(long retryAfterSeconds) {
            this.retryAfterSeconds = retryAfterSeconds;
        }

        long retryAfterSeconds() {
            return retryAfterSeconds;
        }
    }

    private static final class Attempts {
        int count = 0;
        Instant windowStart;

        boolean windowExpired() {
            return windowStart != null && Instant.now().isAfter(windowStart.plus(WINDOW));
        }

        boolean isLimited() {
            return !windowExpired() && count >= MAX_REGISTRATIONS;
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
