package org.freedonia.bloodhound.server.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.freedonia.bloodhound.server.auth.ForgotPasswordRateLimiter.ForgotPasswordRateLimitedException;
import org.junit.jupiter.api.Test;

class ForgotPasswordRateLimiterTest {

    private final ForgotPasswordRateLimiter limiter = new ForgotPasswordRateLimiter();

    @Test
    void firstThreeAttempts_forOneIpAndEmail_eachPassTheirOwnPreCheck() {
        String ip = "10.0.0.1";
        String email = "u1@example.com";
        for (int i = 0; i < 3; i++) {
            limiter.checkAllowed(ip, email); // must not throw
            limiter.recordAttempt(ip, email);
        }
    }

    @Test
    void fourthAttempt_sameIpAndEmail_isBlocked_withAPositiveRetryAfter() {
        String ip = "10.0.0.2";
        String email = "u2@example.com";
        for (int i = 0; i < 3; i++) {
            limiter.recordAttempt(ip, email);
        }

        assertThatThrownBy(() -> limiter.checkAllowed(ip, email)).isInstanceOf(ForgotPasswordRateLimitedException.class);
        assertThat(limiter.remainingLockoutSeconds(ip, email)).isGreaterThan(0).isLessThanOrEqualTo(900);
    }

    @Test
    void sameEmail_rotatingIps_stillBlockedByTheEmailOnlyCap() {
        // The actual point of this test: the IP+email composite cap alone would let an attacker
        // bypass it entirely by rotating source IPs - the separate, looser email-only cap is what
        // catches that case instead.
        String email = "victim@example.com";
        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt("10.0.1." + i, email);
        }

        assertThatThrownBy(() -> limiter.checkAllowed("10.0.1.99", email))
                .isInstanceOf(ForgotPasswordRateLimitedException.class);
    }

    @Test
    void differentEmails_fromTheSameIp_areIndependent() {
        String ip = "10.0.0.3";
        String attackerTarget = "target1@example.com";
        String other = "target2@example.com";
        for (int i = 0; i < 3; i++) {
            limiter.recordAttempt(ip, attackerTarget);
        }

        assertThatThrownBy(() -> limiter.checkAllowed(ip, attackerTarget))
                .isInstanceOf(ForgotPasswordRateLimitedException.class);
        limiter.checkAllowed(ip, other); // must not throw - a different email is unaffected
    }
}
