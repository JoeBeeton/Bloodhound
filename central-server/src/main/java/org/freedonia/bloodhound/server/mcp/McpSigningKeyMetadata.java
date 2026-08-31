package org.freedonia.bloodhound.server.mcp;

import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * A product review found the ephemeral-signing-key restart cost documented on {@link
 * McpAuthorizationServerBeans#mcpSigningKeyPair} (every central-server restart invalidates every
 * previously-issued MCP token, forcing every connected agent to re-authenticate) was silent from
 * an admin's perspective - nothing on the MCP admin page explained why a previously-working MCP
 * client suddenly needs to reconnect. Captured once, at this singleton bean's own construction
 * (the same application-context-refresh phase {@code mcpSigningKeyPair} itself is created in, so
 * this timestamp and the key's actual generation moment coincide for display purposes) - see
 * OrganizationSettingsController for where this is surfaced.
 */
@Component
public class McpSigningKeyMetadata {

    private final Instant generatedAt = Instant.now();

    public Instant generatedAt() {
        return generatedAt;
    }
}
