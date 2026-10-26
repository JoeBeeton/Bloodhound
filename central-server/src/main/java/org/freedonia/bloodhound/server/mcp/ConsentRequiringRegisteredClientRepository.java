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
 * <p>Also grants {@link #MCP_READ_SCOPE} to any client whose requested scope set is empty. A
 * functional review found nothing in this app ever did the other half of that: a DCR-registered
 * client that (reasonably) omits {@code scope} entirely - RFC 7591 leaves the authorization
 * server to decide what to grant in that case - was left with a permanently empty scope set, and
 * the resource-server chain requires {@code SCOPE_mcp.read} (see McpSecurityConfig) - so every
 * self-registered MCP client, the officially-supported way a real client like Claude Desktop
 * connects, could complete the entire OAuth dance and still never successfully call a single
 * tool, always landing on invalid_scope the moment it asked for mcp.read at /oauth2/authorize.
 * mcp.read is this AS's only issuable scope (see McpSecurityConfig's own comment), so granting it
 * here is exactly the RFC's "server decides" step, not a broadening of what any client can get -
 * a client that arrives with a non-empty scope set is left alone. (A client that instead requests
 * {@code mcp.read} explicitly at DCR, e.g. because it read scopes_supported off the
 * protected-resource metadata, is also left alone here - see McpSecurityConfig's
 * dynamicClientRegistrationValidator for why that's no longer rejected before it gets this far.)
 *
 * <p>Also forces {@code requireProofKey(true)} (mandatory PKCE) on every client. A security
 * review found DCR is reachable unauthenticated (rate-limited, see DcrRateLimiter, but not
 * gated on identity) - an attacker can self-register a client named e.g. "Claude Desktop" and
 * send a real user an authorize link for it. Consent being required (see above) already surfaces
 * that this is a separate app the user is granting access to, but without mandatory PKCE, a code
 * that leaked via referrer/browser history/logs after the user approved could still be redeemed
 * by anyone who captured it, not just the party that generated the original request. Forcing it
 * here, at the same save() choke point, closes it for every registration path regardless of
 * what scope/PKCE settings the request itself specified.
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
        settings.requireProofKey(true);
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
