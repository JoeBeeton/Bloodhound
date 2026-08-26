package org.freedonia.bloodhound.webui.auth.dto;

/** Shape returned by central-server's /api/v1/auth/{login,refresh} - includes the raw refresh token. */
public record UpstreamAuthResponse(String accessToken, long expiresIn, String refreshToken, UserSummary user) {}
