package org.freedonia.bloodhound.worker.ratelimit;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-hostname token bucket so a single worker's own concurrency never sends
 * more than {@code permitsPerSecond} requests/second at any one target
 * hostname, regardless of how many probes happen to be in flight for it.
 * This is a per-worker-instance limiter, not a distributed one - it does
 * nothing to stop N different worker replicas from each independently
 * hammering the same hostname at the configured rate. A true cross-worker
 * limit would need a shared store (e.g. Redis) and is out of scope for
 * Phase 1; documented here as a real, known gap rather than silently
 * pretending this is more protective than it is.
 *
 * <p>Deliberately NOT applied to DNS resolution (that traffic goes to our
 * own configured public resolver, not the target's infrastructure) or to
 * per-subdomain dangling-CNAME confirmation requests (each targets a
 * distinct subdomain hostname - one request per host is already polite;
 * there's no repeated-same-host traffic there for a bucket to smooth out).
 * It IS applied to {@code ExposedPathFetcher}, which is the one module that
 * genuinely fires ~20 concurrent requests at the exact same hostname.
 */
public final class HostnameRateLimiter {

    private static final double DEFAULT_PERMITS_PER_SECOND = 12.0;
    private static final HostnameRateLimiter SHARED = new HostnameRateLimiter(DEFAULT_PERMITS_PER_SECOND);

    private final double permitsPerSecond;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public HostnameRateLimiter(double permitsPerSecond) {
        this.permitsPerSecond = permitsPerSecond;
    }

    /** One limiter shared by every module in this worker JVM, keyed by hostname. */
    public static HostnameRateLimiter shared() {
        return SHARED;
    }

    /** Blocks the calling thread until a permit for {@code hostname} is available. */
    public void acquire(String hostname) {
        buckets.computeIfAbsent(hostname, h -> new Bucket(permitsPerSecond)).acquire();
    }

    /**
     * Classic token bucket: refills continuously at {@code permitsPerSecond},
     * capped at a 1-second burst. {@code acquire()} holds the monitor for the
     * duration of any wait, which is the intended behaviour here - it
     * serializes callers targeting the same hostname down to the configured
     * rate rather than letting them all queue up and burst through together.
     */
    private static final class Bucket {
        private final double permitsPerSecond;
        private double availableTokens;
        private long lastRefillNanos;

        Bucket(double permitsPerSecond) {
            this.permitsPerSecond = permitsPerSecond;
            this.availableTokens = permitsPerSecond;
            this.lastRefillNanos = System.nanoTime();
        }

        synchronized void acquire() {
            refill();
            if (availableTokens < 1.0) {
                double deficitSeconds = (1.0 - availableTokens) / permitsPerSecond;
                long sleepMillis = Math.max(1, (long) Math.ceil(deficitSeconds * 1000.0));
                try {
                    Thread.sleep(sleepMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                refill();
            }
            availableTokens = Math.max(0.0, availableTokens - 1.0);
        }

        private void refill() {
            long now = System.nanoTime();
            double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
            availableTokens = Math.min(permitsPerSecond, availableTokens + elapsedSeconds * permitsPerSecond);
            lastRefillNanos = now;
        }
    }
}
