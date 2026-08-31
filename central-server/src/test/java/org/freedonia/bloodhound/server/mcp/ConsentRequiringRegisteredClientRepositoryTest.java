package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

class ConsentRequiringRegisteredClientRepositoryTest {

    private final RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
    private final ConsentRequiringRegisteredClientRepository repository =
            new ConsentRequiringRegisteredClientRepository(delegate);

    private RegisteredClient.Builder client(String clientName) {
        return RegisteredClient.withId("id")
                .clientId("client-id")
                .clientName(clientName)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.com/callback");
    }

    @Test
    void forcesAuthorizationConsentOn_regardlessOfWhatTheCallerRequested() {
        RegisteredClient client = client("A Client")
                .clientSettings(org.springframework.security.oauth2.server.authorization.settings.ClientSettings
                        .builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        repository.save(client);

        RegisteredClient saved = ArgumentCaptorHelper.captureSaved(delegate);
        assertThat(saved.getClientSettings().isRequireAuthorizationConsent()).isTrue();
    }

    @Test
    void shortClientName_isStoredUnchanged() {
        repository.save(client("A Client").build());

        assertThat(ArgumentCaptorHelper.captureSaved(delegate).getClientName()).isEqualTo("A Client");
    }

    @Test
    void overlongClientName_isTruncatedTo200Characters() {
        String longName = "x".repeat(500);

        repository.save(client(longName).build());

        String saved = ArgumentCaptorHelper.captureSaved(delegate).getClientName();
        assertThat(saved).hasSize(200);
        assertThat(saved).isEqualTo("x".repeat(200));
    }

    @Test
    void exactly200Characters_isStoredUnchanged_notOffByOne() {
        String exactlyAtCap = "x".repeat(200);

        repository.save(client(exactlyAtCap).build());

        assertThat(ArgumentCaptorHelper.captureSaved(delegate).getClientName()).isEqualTo(exactlyAtCap);
    }

    /** Small local helper so each test doesn't repeat the ArgumentCaptor boilerplate. */
    private static final class ArgumentCaptorHelper {
        static RegisteredClient captureSaved(RegisteredClientRepository delegate) {
            org.mockito.ArgumentCaptor<RegisteredClient> captor =
                    org.mockito.ArgumentCaptor.forClass(RegisteredClient.class);
            verify(delegate).save(captor.capture());
            return captor.getValue();
        }
    }
}
