package org.freedonia.bloodhound.server.auth;

import java.util.UUID;

/** The authenticated principal attached to the SecurityContext by {@link JwtAuthenticationFilter}. */
public record JwtPrincipal(UUID userId, UUID organizationId, String role, String email) {}
