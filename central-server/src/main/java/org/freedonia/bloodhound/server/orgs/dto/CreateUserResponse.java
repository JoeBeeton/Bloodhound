package org.freedonia.bloodhound.server.orgs.dto;

import org.freedonia.bloodhound.server.orgs.User;

/**
 * Returned exactly once, from the create-user call only - the temporary
 * password is never retrievable again afterward (only its BCrypt hash is
 * stored) and is never logged. The frontend must show it clearly with a
 * "copy" affordance and an explicit "won't be shown again" warning.
 */
public record CreateUserResponse(UserSummary user, String temporaryPassword) {
    public static CreateUserResponse of(User user, String temporaryPassword) {
        return new CreateUserResponse(UserSummary.from(user), temporaryPassword);
    }
}
