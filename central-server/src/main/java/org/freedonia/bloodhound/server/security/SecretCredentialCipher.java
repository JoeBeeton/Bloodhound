package org.freedonia.bloodhound.server.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * AES-256-GCM encryption for credentials that - unlike worker API keys/refresh tokens
 * (see {@link HashUtil}) - must be recovered in full to actually use (e.g. a GitHub token
 * this app later sends on to GitHub's own API), not just verified against a presented
 * value, so one-way hashing doesn't apply. Keyed by {@code BLOODHOUND_SECRETS_ENCRYPTION_KEY}
 * (a base64-encoded 32-byte key), which only ever lives in {@code .env}/the container's
 * environment - never in the database alongside what it protects.
 *
 * <p>Output format: a 12-byte random nonce, followed by the ciphertext (which GCM's own
 * tag is appended to internally) - the nonce travels with the ciphertext since decryption
 * needs the exact same one, and reusing a nonce across encryptions under the same key is
 * the one mistake that breaks GCM's security entirely, so a fresh random nonce is generated
 * per call rather than ever being reused or derived from anything.
 */
@Component
public class SecretCredentialCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_BYTES = 12;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public SecretCredentialCipher(@Value("${bloodhound.server.secrets-encryption-key:}") String base64Key) {
        this.key = base64Key.isBlank() ? null : new SecretKeySpec(Base64.getDecoder().decode(base64Key), "AES");
    }

    /**
     * False when {@code BLOODHOUND_SECRETS_ENCRYPTION_KEY} is unset - callers must check this
     * before offering any encrypted-secret feature, same "disabled, not a bug" convention this
     * codebase already uses for an unset {@code HIBP_API_KEY}.
     */
    public boolean isConfigured() {
        return key != null;
    }

    public byte[] encrypt(String plaintext) {
        requireConfigured();
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("failed to encrypt credential", e);
        }
    }

    public String decrypt(byte[] stored) {
        requireConfigured();
        try {
            byte[] nonce = Arrays.copyOfRange(stored, 0, NONCE_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(stored, NONCE_BYTES, stored.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("failed to decrypt credential - wrong key, or corrupted data", e);
        }
    }

    private void requireConfigured() {
        if (key == null) {
            throw new IllegalStateException("BLOODHOUND_SECRETS_ENCRYPTION_KEY is not configured");
        }
    }
}
