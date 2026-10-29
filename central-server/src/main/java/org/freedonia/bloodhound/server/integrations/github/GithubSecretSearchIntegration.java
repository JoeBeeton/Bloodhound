package org.freedonia.bloodhound.server.integrations.github;

import java.time.Instant;
import java.util.UUID;

/** {@code encryptedToken} is AES-256-GCM ciphertext (see {@link org.freedonia.bloodhound.server.security.SecretCredentialCipher}) - never the raw token. */
public record GithubSecretSearchIntegration(
        UUID id, UUID organizationId, byte[] encryptedToken, boolean enabled, Instant createdAt, Instant updatedAt) {}
