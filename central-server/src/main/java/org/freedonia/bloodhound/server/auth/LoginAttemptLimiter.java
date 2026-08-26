package org.freedonia.bloodhound.server.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Brute-force guard on /auth/login: before this, an attacker with no rate
 * limiting at all could try unlimited passwords against any known email,
 * bounded only by BCrypt's own hashing cost. Keyed by email (case-
 * insensitive) rather than client IP - the realistic threat here is
 * unlimited guesses against one account, which an IP-only limiter wouldn't
 * stop (trivially defeated by rotating source IPs) but an email-keyed one
 * does regardless of where the requests come from. This is a per-instance,
 * in-memory limiter (central-server runs as a single instance in this
 * deployment, unlike the horizontally-scaled workers) - a multi-instance
 * deployment would need a shared store (Redis, or a DB-backed counter) for
 * this to hold across instances; documented as a known scaling gap rather
 * than silently assumed away.
 */
@Component
public class LoginAttemptLimiter {

    private static final int MAX_FAILURES = 10;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, Attempts> byEmail = new ConcurrentHashMap<>();

    public void checkAllowed(String email) {
        Attempts attempts = byEmail.get(key(email));
        if (attempts != null && attempts.isLockedOut()) {
            throw new LoginRateLimitedException();
        }
    }

    public void recordFailure(String email) {
        byEmail.compute(key(email), (k, existing) -> {
            Attempts attempts = existing != null && !existing.windowExpired() ? existing : new Attempts();
            attempts.failureCount++;
            attempts.windowStart = attempts.windowStart == null ? Instant.now() : attempts.windowStart;
            return attempts;
        });
    }

    public void recordSuccess(String email) {
        byEmail.remove(key(email));
    }

    private static String key(String email) {
        return email == null ? "" : email.toLowerCase();
    }

    private static final class Attempts {
        int failureCount = 0;
        Instant windowStart;

        boolean windowExpired() {
            return windowStart != null && Instant.now().isAfter(windowStart.plus(WINDOW));
        }

        boolean isLockedOut() {
            return !windowExpired() && failureCount >= MAX_FAILURES;
        }
    }
}
