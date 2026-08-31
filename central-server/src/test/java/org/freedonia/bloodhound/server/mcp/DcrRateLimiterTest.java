package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.freedonia.bloodhound.server.mcp.DcrRateLimiter.DcrRateLimitedException;
import org.junit.jupiter.api.Test;

class DcrRateLimiterTest {

    private final DcrRateLimiter limiter = new DcrRateLimiter();

    @Test
    void firstFiveAttempts_eachPassTheirOwnPreCheck() {
        // Each registration's pre-check only ever sees attempts recorded strictly before it - the
        // 5th attempt's own checkAllowed still sees only 4 recorded, same "count >= MAX blocks
        // starting at the Nth, not the (N+1)th" boundary LoginAttemptLimiter itself uses.
        String ip = "10.0.0.1";
        for (int i = 0; i < 5; i++) {
            limiter.checkAllowed(ip); // must not throw
            limiter.recordAttempt(ip);
        }
    }

    @Test
    void sixthAttempt_isBlocked_withAPositiveRetryAfter() {
        String ip = "10.0.0.2";
        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt(ip);
        }

        DcrRateLimitedException ex = org.junit.jupiter.api.Assertions.assertThrows(
                DcrRateLimitedException.class, () -> limiter.checkAllowed(ip));

        assertThat(ex.retryAfterSeconds()).isGreaterThan(0).isLessThanOrEqualTo(3600);
    }

    @Test
    void differentIps_areIndependent() {
        String attacker = "10.0.0.3";
        String other = "10.0.0.4";
        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt(attacker);
        }

        assertThatThrownBy(() -> limiter.checkAllowed(attacker)).isInstanceOf(DcrRateLimitedException.class);
        limiter.checkAllowed(other); // must not throw - a different IP is unaffected
    }
}
