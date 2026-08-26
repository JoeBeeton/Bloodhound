package org.freedonia.bloodhound.server.scim;

import java.time.Instant;
import java.util.UUID;

/**
 * The subset of `users` a SCIM client cares about. Kept as this module's own
 * row shape (rather than reusing orgs.User) because SCIM needs external_id
 * and updated_at, which orgs.User doesn't currently expose, and this task is
 * scoped to not touch that shared class.
 */
public record ScimUserRow(
        UUID id,
        UUID organizationId,
        String userName,
        String displayName,
        boolean active,
        String externalId,
        Instant createdAt,
        Instant updatedAt) {}
