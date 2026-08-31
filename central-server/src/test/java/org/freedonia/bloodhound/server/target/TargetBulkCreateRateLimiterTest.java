package org.freedonia.bloodhound.server.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.freedonia.bloodhound.server.target.TargetBulkCreateRateLimiter.TargetBulkCreateRateLimitedException;
import org.junit.jupiter.api.Test;

class TargetBulkCreateRateLimiterTest {

    private final TargetBulkCreateRateLimiter limiter = new TargetBulkCreateRateLimiter();

    @Test
    void firstRequestsUpToTheLimit_eachPassTheirOwnPreCheck() {
        UUID userId = UUID.randomUUID();
        for (int i = 0; i < 10; i++) {
            limiter.checkAllowed(userId); // must not throw
            limiter.recordRequest(userId);
        }
    }

    @Test
    void requestOverTheLimit_isBlocked_withAPositiveRetryAfter() {
        UUID userId = UUID.randomUUID();
        for (int i = 0; i < 10; i++) {
            limiter.recordRequest(userId);
        }

        TargetBulkCreateRateLimitedException ex = org.junit.jupiter.api.Assertions.assertThrows(
                TargetBulkCreateRateLimitedException.class, () -> limiter.checkAllowed(userId));

        assertThat(ex.retryAfterSeconds()).isGreaterThan(0).isLessThanOrEqualTo(60);
    }

    @Test
    void differentUsers_areIndependent() {
        UUID busyUser = UUID.randomUUID();
        UUID quietUser = UUID.randomUUID();
        for (int i = 0; i < 10; i++) {
            limiter.recordRequest(busyUser);
        }

        assertThatThrownBy(() -> limiter.checkAllowed(busyUser)).isInstanceOf(TargetBulkCreateRateLimitedException.class);
        limiter.checkAllowed(quietUser); // must not throw - a different user is unaffected
    }
}
