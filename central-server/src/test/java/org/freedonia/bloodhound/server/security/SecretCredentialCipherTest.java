package org.freedonia.bloodhound.server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class SecretCredentialCipherTest {

    private static final String TEST_KEY = Base64.getEncoder().encodeToString(randomKeyBytes());

    private static byte[] randomKeyBytes() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private final SecretCredentialCipher cipher = new SecretCredentialCipher(TEST_KEY);

    @Test
    void encryptThenDecrypt_recoversTheOriginalPlaintext() {
        String original = "ghp_realGithubTokenShapedValue1234567890";

        byte[] encrypted = cipher.encrypt(original);

        assertThat(cipher.decrypt(encrypted)).isEqualTo(original);
    }

    @Test
    void encrypt_neverProducesTheCiphertextVerbatim() {
        String original = "a-live-looking-secret-value";

        byte[] encrypted = cipher.encrypt(original);

        assertThat(new String(encrypted, java.nio.charset.StandardCharsets.UTF_8)).doesNotContain(original);
    }

    @Test
    void encrypt_isNonDeterministic_sameInputProducesDifferentCiphertext() {
        // Proves a fresh random nonce is actually used each call, not a fixed/derived one -
        // reusing a GCM nonce under the same key is the one mistake that breaks its security.
        String original = "same plaintext every time";

        byte[] first = cipher.encrypt(original);
        byte[] second = cipher.encrypt(original);

        assertThat(first).isNotEqualTo(second);
        assertThat(cipher.decrypt(first)).isEqualTo(original);
        assertThat(cipher.decrypt(second)).isEqualTo(original);
    }

    @Test
    void isConfigured_trueWhenAKeyIsProvided() {
        assertThat(cipher.isConfigured()).isTrue();
    }

    @Test
    void blankKey_isConfiguredFalse_andEncryptThrowsRatherThanSilentlyProceeding() {
        SecretCredentialCipher unconfigured = new SecretCredentialCipher("");

        assertThat(unconfigured.isConfigured()).isFalse();
        assertThatThrownBy(() -> unconfigured.encrypt("anything")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void decryptWithWrongKey_throwsRatherThanReturningGarbage() {
        byte[] encrypted = cipher.encrypt("secret");
        SecretCredentialCipher otherCipher = new SecretCredentialCipher(Base64.getEncoder().encodeToString(randomKeyBytes()));

        assertThatThrownBy(() -> otherCipher.decrypt(encrypted)).isInstanceOf(IllegalStateException.class);
    }
}
