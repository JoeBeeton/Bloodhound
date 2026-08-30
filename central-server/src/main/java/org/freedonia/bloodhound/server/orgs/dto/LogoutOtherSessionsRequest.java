package org.freedonia.bloodhound.server.orgs.dto;

import jakarta.validation.constraints.NotBlank;

/** The caller's own current raw refresh token - not revoked, so this action doesn't also sign the caller themselves out. */
public record LogoutOtherSessionsRequest(@NotBlank String currentRefreshToken) {}
