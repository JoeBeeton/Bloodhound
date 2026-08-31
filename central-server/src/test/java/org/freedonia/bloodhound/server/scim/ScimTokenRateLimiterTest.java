package org.freedonia.bloodhound.server.scim;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.freedonia.bloodhound.server.scim.ScimTokenRateLimiter.ScimTokenRateLimitedException;
import org.junit.jupiter.api.Test;

class ScimTokenRateLimiterTest {

    private final ScimTokenRateLimiter limiter = new ScimTokenRateLimiter();

    @Test
    void firstRequestsUpToTheLimit_eachPassTheirOwnPreCheck() {
        UUID tokenId = UUID.randomUUID();
        for (int i = 0; i < 120; i++) {
            limiter.checkAllowed(tokenId); // must not throw
            limiter.recordRequest(tokenId);
        }
    }

    @Test
    void requestOverTheLimit_isBlocked_withAPositiveRetryAfter() {
        UUID tokenId = UUID.randomUUID();
        for (int i = 0; i < 120; i++) {
            limiter.recordRequest(tokenId);
        }

        ScimTokenRateLimitedException ex = org.junit.jupiter.api.Assertions.assertThrows(
                ScimTokenRateLimitedException.class, () -> limiter.checkAllowed(tokenId));

        assertThat(ex.retryAfterSeconds()).isGreaterThan(0).isLessThanOrEqualTo(60);
    }

    @Test
    void differentTokens_areIndependent() {
        UUID busyToken = UUID.randomUUID();
        UUID quietToken = UUID.randomUUID();
        for (int i = 0; i < 120; i++) {
            limiter.recordRequest(busyToken);
        }

        assertThatThrownBy(() -> limiter.checkAllowed(busyToken)).isInstanceOf(ScimTokenRateLimitedException.class);
        limiter.checkAllowed(quietToken); // must not throw - a different token is unaffected
    }
}
