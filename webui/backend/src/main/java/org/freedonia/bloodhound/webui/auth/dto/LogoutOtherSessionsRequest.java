package org.freedonia.bloodhound.webui.auth.dto;

/** Field name must match central-server's LogoutOtherSessionsRequest exactly (Jackson binds by name). */
public record LogoutOtherSessionsRequest(String currentRefreshToken) {}
