package org.freedonia.bloodhound.server.mcp;

import java.time.Instant;
import java.util.List;

/** See {@link McpConnectionRepository} for where this is read from. */
public record McpConnection(
        String registeredClientId,
        String clientName,
        String principalEmail,
        List<String> scopes,
        Instant lastActiveAt,
        Instant refreshTokenExpiresAt) {}
