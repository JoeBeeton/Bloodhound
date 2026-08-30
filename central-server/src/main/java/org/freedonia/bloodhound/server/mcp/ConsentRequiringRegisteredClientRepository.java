package org.freedonia.bloodhound.server.mcp;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/**
 * Forces {@code requireAuthorizationConsent(true)} on every client that gets saved, regardless of
 * whatever the caller (Dynamic Client Registration, or any manual registration path) set - see
 * McpAuthorizationServerBeans#registeredClientRepository for why this exists. A single choke point
 * rather than trying to remember it at every place a RegisteredClient might get built.
 */
public class ConsentRequiringRegisteredClientRepository implements RegisteredClientRepository {

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
                .build();
        delegate.save(corrected);
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
