package org.freedonia.bloodhound.server.auth.dto;

import org.freedonia.bloodhound.server.auth.AuthResult;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;

public record AuthResponse(String accessToken, long expiresIn, String refreshToken, UserSummary user) {
    public static AuthResponse from(AuthResult result) {
        return new AuthResponse(result.accessToken(), result.expiresIn(), result.refreshToken(), result.user());
    }
}
