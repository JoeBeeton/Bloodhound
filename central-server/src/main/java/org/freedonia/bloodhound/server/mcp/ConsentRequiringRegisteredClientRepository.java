package org.freedonia.bloodhound.server.mcp;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/**
 * Forces {@code requireAuthorizationConsent(true)} on every client that gets saved, regardless of
 * whatever the caller (Dynamic Client Registration, or any manual registration path) set - see
 * McpAuthorizationServerBeans#registeredClientRepository for why this exists. A single choke point
 * rather than trying to remember it at every place a RegisteredClient might get built.
 *
 * <p>Also caps {@code clientName}'s stored length - a security review found Dynamic Client
 * Registration (see DcrRateLimiter) accepts an arbitrary, attacker-supplied client_name with no
 * length limit at all (confirmed live: registered and stored, verbatim, in full, including HTML
 * markup). DcrRateLimiter bounds how many times an attacker can call this endpoint; this bounds
 * how much each individual call can store, so one registration can't itself be an unbounded-size
 * write (e.g. megabytes of text as a single "name").
 *
 * <p>Also grants {@link #MCP_READ_SCOPE} to any client whose requested scope set is empty. RFC
 * 7591 requires a Dynamic Client Registration request to omit {@code scope} entirely and leaves
 * the authorization server to decide what to grant (confirmed live: Spring's own
 * DEFAULT_SCOPE_VALIDATOR rejects a registration that DOES specify one, with "scope must not be
 * set during Dynamic Client Registration"). A functional review found nothing in this app ever
 * did the other half of that: a DCR-registered client was left with a permanently empty scope
 * set, and the resource-server chain requires {@code SCOPE_mcp.read} (see McpSecurityConfig) - so
 * every self-registered MCP client, the officially-supported way a real client like Claude
 * Desktop connects, could complete the entire OAuth dance and still never successfully call a
 * single tool, always landing on invalid_scope the moment it asked for mcp.read at /oauth2/
 * authorize. mcp.read is this AS's only issuable scope (see McpSecurityConfig's own comment), so
 * granting it here is exactly the RFC's "server decides" step, not a broadening of what any
 * client can get - a client that arrives with a non-empty scope set (a manually pre-registered
 * one, if this app ever adds that path) is left alone.
 */
public class ConsentRequiringRegisteredClientRepository implements RegisteredClientRepository {

    /**
     * Generous relative to what any real client integration ever needs (Spring's default consent
     * page just prints this as a plain label) - large enough that no legitimate client_name is
     * ever truncated, small enough that a single registration can't write an unbounded amount of
     * text into one row.
     */
    private static final int MAX_CLIENT_NAME_LENGTH = 200;

    private static final String MCP_READ_SCOPE = "mcp.read";

    private final RegisteredClientRepository delegate;

    public ConsentRequiringRegisteredClientRepository(RegisteredClientRepository delegate) {
        this.delegate = delegate;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        ClientSettings.Builder settings = ClientSettings.withSettings(
                registeredClient.getClientSettings().getSettings());
        settings.requireAuthorizationConsent(true);
        RegisteredClient.Builder builder = RegisteredClient.from(registeredClient)
                .clientSettings(settings.build())
                .clientName(cap(registeredClient.getClientName()));
        if (registeredClient.getScopes().isEmpty()) {
            builder.scope(MCP_READ_SCOPE);
        }
        delegate.save(builder.build());
    }

    private static String cap(String clientName) {
        if (clientName == null || clientName.length() <= MAX_CLIENT_NAME_LENGTH) {
            return clientName;
        }
        return clientName.substring(0, MAX_CLIENT_NAME_LENGTH);
    }

    @Override
    public RegisteredClient findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return delegate.findByClientId(clientId);
    }
}
