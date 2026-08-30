package org.freedonia.bloodhound.server.scim;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ScimTokenTest {

    private ScimToken token(Instant revokedAt, Instant expiresAt) {
        return new ScimToken(UUID.randomUUID(), UUID.randomUUID(), "label", "hash", Instant.now(), revokedAt, expiresAt);
    }

    @Test
    void isActive_noExpiryNoRevocation_alwaysActive() {
        // The deliberate default for a continuous directory-sync credential - see
        // V44__scim_token_expiry.sql.
        ScimToken t = token(null, null);

        assertThat(t.isActive(Instant.now())).isTrue();
        assertThat(t.isActive(Instant.now().plus(10_000, ChronoUnit.DAYS))).isTrue();
    }

    @Test
    void isActive_futureExpiry_active() {
        ScimToken t = token(null, Instant.now().plus(30, ChronoUnit.DAYS));

        assertThat(t.isActive(Instant.now())).isTrue();
    }

    @Test
    void isActive_pastExpiry_notActive() {
        ScimToken t = token(null, Instant.now().minus(1, ChronoUnit.DAYS));

        assertThat(t.isActive(Instant.now())).isFalse();
    }

    @Test
    void isActive_revoked_notActive_evenWithNoExpiry() {
        ScimToken t = token(Instant.now().minus(1, ChronoUnit.DAYS), null);

        assertThat(t.isActive(Instant.now())).isFalse();
    }
}
