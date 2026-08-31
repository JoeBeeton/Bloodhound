package org.freedonia.bloodhound.server.auth.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.AuthenticationService;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

class SamlAuthenticationSuccessHandlerTest {

    private final IdentityProviderRepository identityProviderRepository = mock(IdentityProviderRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SsoHandoffCodeRepository handoffCodeRepository = mock(SsoHandoffCodeRepository.class);
    private final SamlAuthenticationSuccessHandler handler = new SamlAuthenticationSuccessHandler(
            identityProviderRepository,
            userRepository,
            authenticationService,
            handoffCodeRepository,
            "http://localhost:8090/sso/callback");

    private IdentityProvider idp(String emailAttribute) {
        return new IdentityProvider(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "okta",
                "https://idp.example.com/entity",
                "https://idp.example.com/sso",
                "cert",
                emailAttribute,
                null,
                true,
                Instant.now(),
                Instant.now());
    }

    private Saml2Authentication samlAuth(String registrationId, Map<String, List<Object>> attributes) {
        var principal = new DefaultSaml2AuthenticatedPrincipal("user1", attributes);
        principal.setRelyingPartyRegistrationId(registrationId);
        return new Saml2Authentication(principal, "saml-response", List.of());
    }

    @Test
    void unknownRegistrationId_redirectsWithAnErrorParam_neverThrows_neverIssuesTokens() throws Exception {
        when(identityProviderRepository.findByRegistrationId("stale-idp")).thenReturn(Optional.empty());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, samlAuth("stale-idp", Map.of()));

        assertThat(response.getRedirectedUrl()).startsWith("http://localhost:8090/sso/callback?error=");
        assertThat(decodedErrorParam(response)).contains("unrecognized identity provider");
        verify(authenticationService, never()).issueTokens(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void assertionMissingConfiguredEmailAttribute_redirectsWithAnErrorParam_neverThrows() throws Exception {
        when(identityProviderRepository.findByRegistrationId("okta")).thenReturn(Optional.of(idp("email")));
        MockHttpServletResponse response = new MockHttpServletResponse();
        // The assertion carries a *different* attribute name than the org's configured
        // email_attribute_name - the realistic real-world mismatch this fix targets.
        Saml2Authentication auth =
                samlAuth("okta", Map.of("mail", List.of("user1@example.com")));

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, auth);

        assertThat(response.getRedirectedUrl()).startsWith("http://localhost:8090/sso/callback?error=");
        assertThat(decodedErrorParam(response)).contains("missing the configured email attribute");
        verify(authenticationService, never()).issueTokens(org.mockito.ArgumentMatchers.any());
    }

    private static String decodedErrorParam(MockHttpServletResponse response) {
        String url = response.getRedirectedUrl();
        String encoded = url.substring(url.indexOf("error=") + "error=".length());
        return URLDecoder.decode(encoded, StandardCharsets.UTF_8);
    }

    @Test
    void extractsFirstAttribute_whenPresent() {
        var principal = new DefaultSaml2AuthenticatedPrincipal(
                "user1", Map.of("email", List.of("user1@example.com")));
        assertThat(SamlAuthenticationSuccessHandler.firstAttribute(principal, "email"))
                .contains("user1@example.com");
    }

    @Test
    void returnsEmpty_whenAttributeMissingEntirely() {
        var principal = new DefaultSaml2AuthenticatedPrincipal("user1", Map.of());
        assertThat(SamlAuthenticationSuccessHandler.firstAttribute(principal, "email")).isEmpty();
    }

    @Test
    void returnsEmpty_whenAttributePresentButValueListEmpty() {
        var principal = new DefaultSaml2AuthenticatedPrincipal("user1", Map.of("email", List.of()));
        assertThat(SamlAuthenticationSuccessHandler.firstAttribute(principal, "email")).isEmpty();
    }

    @Test
    void takesFirstValue_whenMultiValued() {
        var principal = new DefaultSaml2AuthenticatedPrincipal(
                "user1", Map.of("email", List.of("primary@example.com", "secondary@example.com")));
        assertThat(SamlAuthenticationSuccessHandler.firstAttribute(principal, "email"))
                .contains("primary@example.com");
    }

    @Test
    void isCaseSensitiveOnAttributeName_realIdpsVaryHere() {
        // Real IdPs use wildly different attribute-name conventions (bare "email" vs.
        // "urn:oid:..." style) - this is exactly why email_attribute_name is admin-configurable
        // per org rather than a single hardcoded guess. Confirms the lookup doesn't silently
        // fall back to some other key on a mismatch.
        var principal = new DefaultSaml2AuthenticatedPrincipal(
                "user1", Map.of("urn:oid:0.9.2342.19200300.100.1.3", List.of("user1@example.com")));
        assertThat(SamlAuthenticationSuccessHandler.firstAttribute(principal, "email")).isEmpty();
        assertThat(SamlAuthenticationSuccessHandler.firstAttribute(
                        principal, "urn:oid:0.9.2342.19200300.100.1.3"))
                .contains("user1@example.com");
    }
}
