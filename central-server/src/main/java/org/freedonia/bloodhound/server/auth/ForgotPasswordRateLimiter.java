package org.freedonia.bloodhound.server.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Guards the public, unauthenticated POST /api/v1/auth/forgot-password (see AuthController) -
 * same in-memory fixed-window shape as {@link DcrRateLimiter}, but two independent caps rather
 * than one, each closing a different abuse case a single IP-keyed or single email-keyed limiter
 * would miss on its own:
 *
 * <ul>
 *   <li>{@code byIpAndEmail}, tight (3 / 15 min): one source hammering one target.
 *   <li>{@code byEmail}, looser (5 / hour): the same target inbox-bombed via rotating source IPs,
 *       which an IP-and-email-composite key alone can't see (every new IP mints a fresh bucket).
 * </ul>
 *
 * Deliberately a separate instance from {@link LoginAttemptLimiter}, even though both are
 * email-keyed fixed-window limiters - a flood of forgot-password *requests* against an email must
 * not also lock that account out of a real login attempt, which sharing one instance would do.
 */
@Component
public class ForgotPasswordRateLimiter {

    private static final int MAX_PER_IP_AND_EMAIL = 3;
    private static final Duration IP_AND_EMAIL_WINDOW = Duration.ofMinutes(15);
    private static final int MAX_PER_EMAIL = 5;
    private static final Duration EMAIL_WINDOW = Duration.ofHours(1);

    private final ConcurrentHashMap<String, Attempts> byIpAndEmail = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Attempts> byEmail = new ConcurrentHashMap<>();

    public void checkAllowed(String ip, String email) {
        if (isLimited(byIpAndEmail.get(ipAndEmailKey(ip, email)), MAX_PER_IP_AND_EMAIL, IP_AND_EMAIL_WINDOW)
                || isLimited(byEmail.get(emailKey(email)), MAX_PER_EMAIL, EMAIL_WINDOW)) {
            throw new ForgotPasswordRateLimitedException();
        }
    }

    public void recordAttempt(String ip, String email) {
        record(byIpAndEmail, ipAndEmailKey(ip, email), IP_AND_EMAIL_WINDOW);
        record(byEmail, emailKey(email), EMAIL_WINDOW);
    }

    /** The larger of the two layers' remaining lockout, for the endpoint's Retry-After header - same reasoning as LoginAttemptLimiter's own method. 0 if neither is currently active. */
    public long remainingLockoutSeconds(String ip, String email) {
        return Math.max(
                remaining(byIpAndEmail.get(ipAndEmailKey(ip, email)), MAX_PER_IP_AND_EMAIL, IP_AND_EMAIL_WINDOW),
                remaining(byEmail.get(emailKey(email)), MAX_PER_EMAIL, EMAIL_WINDOW));
    }

    /** Same unbounded-map-growth concern DcrRateLimiter/LoginAttemptLimiter already document for their own maps. */
    @Scheduled(fixedRate = 15, initialDelay = 15, timeUnit = TimeUnit.MINUTES)
    void evictExpiredEntries() {
        byIpAndEmail.values().removeIf(a -> a.windowExpired(IP_AND_EMAIL_WINDOW));
        byEmail.values().removeIf(a -> a.windowExpired(EMAIL_WINDOW));
    }

    private static boolean isLimited(Attempts attempts, int max, Duration window) {
        return attempts != null && !attempts.windowExpired(window) && attempts.count >= max;
    }

    private static long remaining(Attempts attempts, int max, Duration window) {
        if (!isLimited(attempts, max, window)) {
            return 0;
        }
        Duration left = Duration.between(Instant.now(), attempts.windowStart.plus(window));
        return Math.max(0, left.toSeconds());
    }

    private static void record(ConcurrentHashMap<String, Attempts> map, String key, Duration window) {
        map.compute(key, (k, existing) -> {
            Attempts attempts = existing != null && !existing.windowExpired(window) ? existing : new Attempts();
            attempts.count++;
            attempts.windowStart = attempts.windowStart == null ? Instant.now() : attempts.windowStart;
            return attempts;
        });
    }

    private static String ipAndEmailKey(String ip, String email) {
        return (ip == null ? "" : ip) + "|" + emailKey(email);
    }

    private static String emailKey(String email) {
        return email == null ? "" : email.toLowerCase();
    }

    static final class ForgotPasswordRateLimitedException extends RuntimeException {}

    private static final class Attempts {
        int count = 0;
        Instant windowStart;

        boolean windowExpired(Duration window) {
            return windowStart != null && Instant.now().isAfter(windowStart.plus(window));
        }
    }
}
