package org.freedonia.bloodhound.server.apikey;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ApiKeyTest {

    private ApiKey key(Instant expiresAt, Instant revokedAt) {
        return new ApiKey(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "label",
                "bhk_abc123",
                "hash",
                Instant.now().minus(1, ChronoUnit.DAYS),
                expiresAt,
                null,
                revokedAt);
    }

    @Test
    void unexpiredUnrevoked_isActive() {
        ApiKey key = key(Instant.now().plus(1, ChronoUnit.DAYS), null);
        assertThat(key.isActive(Instant.now())).isTrue();
    }

    @Test
    void expired_isNotActive() {
        ApiKey key = key(Instant.now().minus(1, ChronoUnit.MINUTES), null);
        assertThat(key.isActive(Instant.now())).isFalse();
    }

    @Test
    void revoked_isNotActive_evenIfUnexpired() {
        ApiKey key = key(Instant.now().plus(1, ChronoUnit.DAYS), Instant.now().minus(1, ChronoUnit.MINUTES));
        assertThat(key.isActive(Instant.now())).isFalse();
    }

    @Test
    void expiresExactlyNow_isNotActive() {
        Instant now = Instant.now();
        ApiKey key = key(now, null);
        assertThat(key.isActive(now)).isFalse();
    }
}
