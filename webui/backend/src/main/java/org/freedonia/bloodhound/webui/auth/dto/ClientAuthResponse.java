package org.freedonia.bloodhound.webui.auth.dto;

/** Shape returned to the browser - the raw refresh token never leaves this service; it becomes an HttpOnly cookie. */
public record ClientAuthResponse(String accessToken, long expiresIn, UserSummary user) {
    public static ClientAuthResponse from(UpstreamAuthResponse upstream) {
        return new ClientAuthResponse(upstream.accessToken(), upstream.expiresIn(), upstream.user());
    }
}
