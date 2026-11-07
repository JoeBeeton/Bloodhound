package org.freedonia.bloodhound.server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class LoginAttemptLimiterTest {

    private final LoginAttemptLimiter limiter = new LoginAttemptLimiter();

    private void fail(String ip, String email, int times) {
        for (int i = 0; i < times; i++) {
            limiter.recordFailure(ip, email);
        }
    }

    @Test
    void tooManyFailuresFromOneSource_locksThatSourceForThatAccount() {
        fail("198.51.100.1", "victim@example.com", LoginAttemptLimiter.MAX_FAILURES_PER_IP_AND_EMAIL);

        assertThatThrownBy(() -> limiter.checkAllowed("198.51.100.1", "victim@example.com"))
                .isInstanceOf(LoginRateLimitedException.class);
        assertThat(limiter.remainingLockoutSeconds("198.51.100.1", "victim@example.com")).isPositive();
    }

    @Test
    void oneAttackersFailures_doNotLockTheRealUserOutFromTheirOwnAddress() {
        fail("198.51.100.1", "victim@example.com", LoginAttemptLimiter.MAX_FAILURES_PER_IP_AND_EMAIL);

        assertThatCode(() -> limiter.checkAllowed("203.0.113.7", "Victim@Example.com")).doesNotThrowAnyException();
    }

    @Test
    void sprayingManyAccountsFromOneSource_locksTheSourceForEveryAccount() {
        for (int i = 0; i < LoginAttemptLimiter.MAX_FAILURES_PER_IP; i++) {
            limiter.recordFailure("198.51.100.1", "user" + i + "@example.com");
        }

        assertThatThrownBy(() -> limiter.checkAllowed("198.51.100.1", "fresh@example.com"))
                .isInstanceOf(LoginRateLimitedException.class);
        assertThatCode(() -> limiter.checkAllowed("203.0.113.7", "fresh@example.com")).doesNotThrowAnyException();
    }

    @Test
    void distributedGuessingAgainstOneAccount_locksTheAccountEverywhere() {
        int perSource = LoginAttemptLimiter.MAX_FAILURES_PER_IP_AND_EMAIL - 1;
        int sources = LoginAttemptLimiter.MAX_FAILURES_PER_EMAIL / perSource + 1;
        for (int s = 0; s < sources; s++) {
            fail("198.51.100." + s, "victim@example.com", perSource);
        }

        assertThatThrownBy(() -> limiter.checkAllowed("203.0.113.7", "victim@example.com"))
                .isInstanceOf(LoginRateLimitedException.class);
    }

    @Test
    void success_clearsThatSourcesLockoutForTheAccount() {
        fail("198.51.100.1", "u@example.com", LoginAttemptLimiter.MAX_FAILURES_PER_IP_AND_EMAIL - 1);
        limiter.recordSuccess("198.51.100.1", "u@example.com");
        fail("198.51.100.1", "u@example.com", LoginAttemptLimiter.MAX_FAILURES_PER_IP_AND_EMAIL - 1);

        assertThatCode(() -> limiter.checkAllowed("198.51.100.1", "u@example.com")).doesNotThrowAnyException();
    }

    @Test
    void noClientIp_fallsBackToPerEmailLockout() {
        fail(null, "u@example.com", LoginAttemptLimiter.MAX_FAILURES_PER_IP_AND_EMAIL);

        assertThatThrownBy(() -> limiter.checkAllowed("u@example.com")).isInstanceOf(LoginRateLimitedException.class);
    }

    @Test
    void internalProxyAddress_isNotTreatedAsOneSharedClient() {
        // e.g. an older webui not forwarding X-Forwarded-For: every user would arrive from it.
        for (int i = 0; i < LoginAttemptLimiter.MAX_FAILURES_PER_IP; i++) {
            limiter.recordFailure("172.20.0.4", "user" + i + "@example.com");
        }

        assertThatCode(() -> limiter.checkAllowed("172.20.0.4", "someone-else@example.com")).doesNotThrowAnyException();
        assertThat(LoginAttemptLimiter.isInternalAddress("10.1.2.3")).isTrue();
        assertThat(LoginAttemptLimiter.isInternalAddress("::1")).isTrue();
        assertThat(LoginAttemptLimiter.isInternalAddress("203.0.113.7")).isFalse();
    }
}
