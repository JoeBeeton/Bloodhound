package org.freedonia.bloodhound.server.auth;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Brute-force guard on every password-entry point (/auth/login, the MCP form login, and the
 * self-service password change). Three independent windows, any one of which locks:
 *
 * <ul>
 *   <li>per (client IP, email), {@value #MAX_FAILURES_PER_IP_AND_EMAIL} failures - the normal
 *       "you mistyped too often" lockout, scoped to the source that's failing;
 *   <li>per client IP across all emails, {@value #MAX_FAILURES_PER_IP} - password spraying (a
 *       few guesses against every account from one source);
 *   <li>per email across all IPs, {@value #MAX_FAILURES_PER_EMAIL} - a distributed guessing run
 *       against one account from rotating source IPs.
 * </ul>
 *
 * <p>A review found the first version was keyed by email alone at 10 failures: anyone who knew
 * an address could lock that user out of login indefinitely (10 junk attempts every 15 minutes -
 * the lockout applies even to the correct password), while spraying across many accounts went
 * completely unthrottled. Scoping the tight limit to (IP, email) means a single attacker can now
 * only lock themselves out; locking a real user out needs the much larger per-email budget spent
 * from several source IPs, each capped by the per-IP window.
 *
 * <p>A null/blank client IP (a caller with no request to hand) skips the per-IP window and keys
 * (IP, email) as ("", email) - i.e. it degrades to the old per-email behavior for that caller. So
 * does a private/loopback address: that's never a real browser, only an internal hop (webui, if
 * it isn't forwarding the client address - e.g. an older webui deployed alongside a newer
 * central-server), and treating it as one client would put every user behind a single shared
 * per-IP window that one attacker could exhaust for all of them.
 *
 * <p>Per-instance and in-memory (central-server runs as a single instance in this deployment,
 * unlike the horizontally-scaled workers) - a multi-instance deployment would need a shared store
 * (Redis, or a DB-backed counter) for this to hold across instances; documented as a known
 * scaling gap rather than silently assumed away.
 */
@Component
public class LoginAttemptLimiter {

    static final int MAX_FAILURES_PER_IP_AND_EMAIL = 10;
    static final int MAX_FAILURES_PER_IP = 30;
    static final int MAX_FAILURES_PER_EMAIL = 50;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, Attempts> byIpAndEmail = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Attempts> byIp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Attempts> byEmail = new ConcurrentHashMap<>();

    public void checkAllowed(String clientIp, String email) {
        if (remainingLockoutSeconds(clientIp, email) > 0) {
            throw new LoginRateLimitedException();
        }
    }

    public void recordFailure(String clientIp, String email) {
        record(byIpAndEmail, ipAndEmailKey(clientIp, email));
        record(byEmail, emailKey(email));
        if (hasIp(clientIp)) {
            record(byIp, clientIp);
        }
    }

    /** Clears this source's own lockout for the account, and the account-wide counter - not the IP-wide one, so one success can't launder a spraying run's other failures. */
    public void recordSuccess(String clientIp, String email) {
        byIpAndEmail.remove(ipAndEmailKey(clientIp, email));
        byEmail.remove(emailKey(email));
    }

    /** No client IP available - see the class javadoc. */
    public void checkAllowed(String email) {
        checkAllowed(null, email);
    }

    public void recordFailure(String email) {
        recordFailure(null, email);
    }

    public void recordSuccess(String email) {
        recordSuccess(null, email);
    }

    public long remainingLockoutSeconds(String email) {
        return remainingLockoutSeconds(null, email);
    }

    /**
     * How much longer this attempt is locked out (the longest of whichever windows are locked),
     * for the login endpoint's Retry-After header - a product review found a rate-limited login
     * previously showed the same generic "something went wrong, try again" message as any other
     * failure, which invites immediately retrying the exact thing that's being throttled. 0 if
     * not currently locked out.
     */
    public long remainingLockoutSeconds(String clientIp, String email) {
        List<Long> remaining = List.of(
                remaining(byIpAndEmail.get(ipAndEmailKey(clientIp, email)), MAX_FAILURES_PER_IP_AND_EMAIL),
                remaining(byEmail.get(emailKey(email)), MAX_FAILURES_PER_EMAIL),
                hasIp(clientIp) ? remaining(byIp.get(clientIp), MAX_FAILURES_PER_IP) : 0L);
        return remaining.stream().mapToLong(Long::longValue).max().orElse(0);
    }

    /**
     * A security review found these maps only ever shrank on success - a failed attempt against a
     * made-up email adds an entry that nothing ever removes otherwise. The login endpoints are
     * unauthenticated, so an attacker submitting failures against many distinct/synthetic emails
     * (or from many IPs) grew them without bound - eventual heap-exhaustion DoS. Sweeping
     * expired-window entries on a timer bounds them to roughly "what failed within the last window".
     */
    @Scheduled(fixedRate = 15, initialDelay = 15, timeUnit = java.util.concurrent.TimeUnit.MINUTES)
    void evictExpiredEntries() {
        byIpAndEmail.values().removeIf(Attempts::windowExpired);
        byIp.values().removeIf(Attempts::windowExpired);
        byEmail.values().removeIf(Attempts::windowExpired);
    }

    private static void record(ConcurrentHashMap<String, Attempts> map, String key) {
        map.compute(key, (k, existing) -> {
            Attempts attempts = existing != null && !existing.windowExpired() ? existing : new Attempts();
            attempts.failureCount++;
            attempts.windowStart = attempts.windowStart == null ? Instant.now() : attempts.windowStart;
            return attempts;
        });
    }

    private static long remaining(Attempts attempts, int maxFailures) {
        if (attempts == null || !attempts.isLockedOut(maxFailures)) {
            return 0;
        }
        return Math.max(1, Duration.between(Instant.now(), attempts.windowStart.plus(WINDOW)).toSeconds());
    }

    private static boolean hasIp(String clientIp) {
        return clientIp != null && !clientIp.isBlank() && !isInternalAddress(clientIp);
    }

    /** Literal addresses only (getRemoteAddr() never returns a hostname) - anything that doesn't parse as one is treated as a real, external client. */
    static boolean isInternalAddress(String clientIp) {
        if (!clientIp.matches("[0-9A-Fa-f:.]+")) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(clientIp);
            byte[] bytes = address.getAddress();
            return address.isLoopbackAddress()
                    || address.isSiteLocalAddress()
                    || address.isLinkLocalAddress()
                    || (bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static String emailKey(String email) {
        return email == null ? "" : email.toLowerCase();
    }

    private static String ipAndEmailKey(String clientIp, String email) {
        return (hasIp(clientIp) ? clientIp : "") + "|" + emailKey(email);
    }

    private static final class Attempts {
        int failureCount = 0;
        Instant windowStart;

        boolean windowExpired() {
            return windowStart != null && Instant.now().isAfter(windowStart.plus(WINDOW));
        }

        boolean isLockedOut(int maxFailures) {
            return !windowExpired() && failureCount >= maxFailures;
        }
    }
}
