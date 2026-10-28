package org.freedonia.bloodhound.server.orgs.dto;

import org.freedonia.bloodhound.server.orgs.User;

/**
 * Returned from user creation now that there's no temporary password to hand back at all - see
 * OrgUserController#create's own javadoc for why. Deliberately has no password-shaped field: an
 * admin-reset's CreateUserResponse genuinely has one to show, and keeping this a separate type
 * (rather than a null temporaryPassword on the same shape) means the frontend can't accidentally
 * render a field that was never meant to exist for this flow.
 */
public record InviteSentResponse(UserSummary user) {
    public static InviteSentResponse of(User user) {
        return new InviteSentResponse(UserSummary.from(user));
    }
}
