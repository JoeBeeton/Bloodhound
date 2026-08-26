package org.freedonia.bloodhound.server.auth;

import java.util.UUID;
import org.freedonia.bloodhound.server.orgs.dto.UserSummary;

public record AuthResult(
        String accessToken, long expiresIn, String refreshToken, UUID refreshTokenId, UserSummary user) {}
