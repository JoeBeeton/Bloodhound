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
 * write (e.g. megabytes of text as a single "name"). The rest of client_name's content is left
 * alone: client_name is meant to reach Spring's own default consent page as a human-readable
 * label, but confirmed live that a self-registered (Dynamic-Client-Registration) client's own
 * scope set is always empty - requesting no scope at /oauth2/authorize skips the consent screen
 * entirely (nothing to consent to), and requesting any actual scope (e.g. mcp.read) is rejected
 * outright as invalid_scope, since the client was never granted it. So a DCR-registered client's
 * client_name structurally never reaches the consent page at all today, independent of whatever
 * escaping that page does or doesn't apply - not relied upon as the actual mitigation here, just
 * noted as the current reality.
 */
public class ConsentRequiringRegisteredClientRepository implements RegisteredClientRepository {

    /**
     * Generous relative to what any real client integration ever needs (Spring's default consent
     * page just prints this as a plain label) - large enough that no legitimate client_name is
     * ever truncated, small enough that a single registration can't write an unbounded amount of
     * text into one row.
     */
    private static final int MAX_CLIENT_NAME_LENGTH = 200;

    private final RegisteredClientRepository delegate;

    public ConsentRequiringRegisteredClientRepository(RegisteredClientRepository delegate) {
        this.delegate = delegate;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        ClientSettings.Builder settings = ClientSettings.withSettings(
                registeredClient.getClientSettings().getSettings());
        settings.requireAuthorizationConsent(true);
        RegisteredClient corrected = RegisteredClient.from(registeredClient)
                .clientSettings(settings.build())
                .clientName(cap(registeredClient.getClientName()))
                .build();
        delegate.save(corrected);
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
