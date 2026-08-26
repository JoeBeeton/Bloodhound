package org.freedonia.bloodhound.worker.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HostnameRateLimiterTest {

    @Test
    void burstsUpToOneSecondsWorthOfPermitsThenThrottles() {
        HostnameRateLimiter limiter = new HostnameRateLimiter(10.0);
        long start = System.nanoTime();
        for (int i = 0; i < 10; i++) {
            limiter.acquire("example.com");
        }
        long burstElapsedMs = (System.nanoTime() - start) / 1_000_000;
        // the bucket starts full (10 tokens for a 10/s limiter), so 10 immediate
        // acquisitions should not have needed to sleep at all.
        assertThat(burstElapsedMs).isLessThan(200);

        start = System.nanoTime();
        limiter.acquire("example.com");
        long extraPermitElapsedMs = (System.nanoTime() - start) / 1_000_000;
        // the bucket is now empty, so the 11th permit within the same second
        // must wait roughly 1/10s = 100ms for a token to refill.
        assertThat(extraPermitElapsedMs).isGreaterThanOrEqualTo(50);
    }

    @Test
    void hostnamesAreIndependentBuckets() {
        HostnameRateLimiter limiter = new HostnameRateLimiter(1.0);
        limiter.acquire("a.example.com");
        long start = System.nanoTime();
        // a different hostname must not be throttled by a.example.com's exhausted bucket
        limiter.acquire("b.example.com");
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertThat(elapsedMs).isLessThan(200);
    }
}
