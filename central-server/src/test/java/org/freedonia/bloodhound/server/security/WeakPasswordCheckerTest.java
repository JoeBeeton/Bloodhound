package org.freedonia.bloodhound.server.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class WeakPasswordCheckerTest {

    private final WeakPasswordChecker checker = new WeakPasswordChecker();

    @Test
    void commonPassword_isWeak() {
        assertThat(checker.isWeak("password1", "someone@example.com")).isTrue();
    }

    @Test
    void commonPassword_matchIsCaseInsensitive() {
        assertThat(checker.isWeak("PaSsWoRd1", "someone@example.com")).isTrue();
    }

    @Test
    void genuinelyRandomPassword_isNotWeak() {
        assertThat(checker.isWeak("xK9!qR2z#mP7wL4c", "someone@example.com")).isFalse();
    }

    @Test
    void passwordEqualToTheFullEmail_isWeak() {
        assertThat(checker.isWeak("someone@example.com", "someone@example.com")).isTrue();
    }

    @Test
    void passwordEqualToTheEmailLocalPart_isWeak() {
        assertThat(checker.isWeak("someone", "someone@example.com")).isTrue();
    }

    @Test
    void emailComparisonIsCaseInsensitive() {
        assertThat(checker.isWeak("SOMEONE", "someone@example.com")).isTrue();
    }

    @Test
    void unrelatedPasswordAgainstADifferentEmail_isNotWeak() {
        assertThat(checker.isWeak("xK9!qR2z#mP7wL4c", "other@example.com")).isFalse();
    }

    @Test
    void nullEmail_doesNotThrow_onlyChecksTheCommonList() {
        assertThat(checker.isWeak("xK9!qR2z#mP7wL4c", null)).isFalse();
        assertThat(checker.isWeak("password1", null)).isTrue();
    }
}
