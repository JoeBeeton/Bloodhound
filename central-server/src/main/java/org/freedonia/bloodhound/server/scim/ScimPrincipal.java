package org.freedonia.bloodhound.server.scim;

import java.util.UUID;

/** The authenticated principal attached to the SecurityContext by {@link ScimTokenAuthFilter}. */
public record ScimPrincipal(UUID organizationId, String tokenLabel) {}
