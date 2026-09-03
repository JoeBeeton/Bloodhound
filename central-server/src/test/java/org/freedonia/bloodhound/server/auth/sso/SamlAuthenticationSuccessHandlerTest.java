package org.freedonia.bloodhound.server.auth.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
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
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertionAccessor;

class SamlAuthenticationSuccessHandlerTest {

    private final IdentityProviderRepository identityProviderRepository = mock(IdentityProviderRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final SsoHandoffCodeRepository handoffCodeRepository = mock(SsoHandoffCodeRepository.class);
    private final SamlAuthenticationSuccessHandler handler = new SamlAuthenticationSuccessHandler(
            identityProviderRepository, userRepository, handoffCodeRepository, "http://localhost:8090/sso/callback");

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

    /**
     * A security review found the original version of this helper - a plain Saml2Authentication
     * wrapping a DefaultSaml2AuthenticatedPrincipal with setRelyingPartyRegistrationId() called on
     * it directly - didn't match what OpenSaml5AuthenticationProvider (the provider actually wired
     * up since this app's Spring Boot 4 migration) constructs in production: that provider carries
     * registrationId on the Saml2AssertionAuthentication itself, and never calls the principal's
     * setter at all (confirmed live and via the library's own bytecode). The old helper shape let
     * every test in this file pass while the real code path had been silently broken since that
     * migration - this constructs the real runtime type instead, so these tests actually exercise
     * what production receives.
     */
    private User disabledUser() {
        return new User(
                UUID.randomUUID(), UUID.randomUUID(), "user1@example.com", "User One", null, "SAML", "VIEWER",
                "DISABLED", Instant.now(), true, null);
    }

    private Saml2Authentication samlAuth(String registrationId, Map<String, List<Object>> attributes) {
        var principal = new DefaultSaml2AuthenticatedPrincipal("user1", attributes);
        Saml2ResponseAssertionAccessor assertion = mock(Saml2ResponseAssertionAccessor.class);
        return new Saml2AssertionAuthentication(principal, assertion, List.of(), registrationId);
    }

    @Test
    void registrationId_readFromTheAuthenticationItself_notThePrincipal() throws Exception {
        // The actual regression this guards: registrationId must be resolved via
        // Saml2AssertionAuthentication#getRelyingPartyRegistrationId(), the real runtime type
        // OpenSaml5AuthenticationProvider constructs - not DefaultSaml2AuthenticatedPrincipal's
        // own getRelyingPartyRegistrationId(), which nothing in production ever populates and
        // which always returns null. Every real SAML login was hitting the "unknown identity
        // provider" branch below for exactly this reason until this fix. Stops at the
        // disabled-user checkpoint (a real, simple-to-construct branch) rather than mocking all
        // the way through token issuance - reaching it at all already proves registrationId and
        // the email attribute both resolved correctly.
        when(identityProviderRepository.findByRegistrationId("okta")).thenReturn(Optional.of(idp("email")));
        when(userRepository.findOrCreateSamlUser(
                        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(), eq("user1@example.com"), org.mockito.ArgumentMatchers.any()))
                .thenReturn(disabledUser());
        MockHttpServletResponse response = new MockHttpServletResponse();
        Saml2Authentication auth = samlAuth("okta", Map.of("email", List.of("user1@example.com")));

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, auth);

        verify(identityProviderRepository).findByRegistrationId("okta");
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void unknownRegistrationId_redirectsWithAnErrorParam_neverThrows_neverCreatesHandoffCode() throws Exception {
        when(identityProviderRepository.findByRegistrationId("stale-idp")).thenReturn(Optional.empty());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, samlAuth("stale-idp", Map.of()));

        assertThat(response.getRedirectedUrl()).startsWith("http://localhost:8090/sso/callback?error=");
        assertThat(decodedErrorParam(response)).contains("unrecognized identity provider");
        verify(handoffCodeRepository, never()).create(org.mockito.ArgumentMatchers.any());
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
        verify(handoffCodeRepository, never()).create(org.mockito.ArgumentMatchers.any());
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
