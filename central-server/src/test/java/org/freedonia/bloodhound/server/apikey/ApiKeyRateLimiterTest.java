package org.freedonia.bloodhound.server.apikey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.freedonia.bloodhound.server.apikey.ApiKeyRateLimiter.ApiKeyRateLimitedException;
import org.junit.jupiter.api.Test;

class ApiKeyRateLimiterTest {

    private final ApiKeyRateLimiter limiter = new ApiKeyRateLimiter();

    @Test
    void firstRequestsUpToTheLimit_eachPassTheirOwnPreCheck() {
        UUID keyId = UUID.randomUUID();
        for (int i = 0; i < 120; i++) {
            limiter.checkAllowed(keyId); // must not throw
            limiter.recordRequest(keyId);
        }
    }

    @Test
    void requestOverTheLimit_isBlocked_withAPositiveRetryAfter() {
        UUID keyId = UUID.randomUUID();
        for (int i = 0; i < 120; i++) {
            limiter.recordRequest(keyId);
        }

        ApiKeyRateLimitedException ex = org.junit.jupiter.api.Assertions.assertThrows(
                ApiKeyRateLimitedException.class, () -> limiter.checkAllowed(keyId));

        assertThat(ex.retryAfterSeconds()).isGreaterThan(0).isLessThanOrEqualTo(60);
    }

    @Test
    void differentKeys_areIndependent() {
        UUID busyKey = UUID.randomUUID();
        UUID quietKey = UUID.randomUUID();
        for (int i = 0; i < 120; i++) {
            limiter.recordRequest(busyKey);
        }

        assertThatThrownBy(() -> limiter.checkAllowed(busyKey)).isInstanceOf(ApiKeyRateLimitedException.class);
        limiter.checkAllowed(quietKey); // must not throw - a different key is unaffected
    }
}
