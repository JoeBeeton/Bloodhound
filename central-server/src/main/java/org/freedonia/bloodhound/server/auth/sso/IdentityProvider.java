package org.freedonia.bloodhound.server.auth.sso;

import java.time.Instant;
import java.util.UUID;

public record IdentityProvider(
        UUID id,
        UUID organizationId,
        String registrationId,
        String idpEntityId,
        String idpSsoUrl,
        String idpX509Cert,
        String emailAttributeName,
        String displayNameAttributeName,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt) {}
