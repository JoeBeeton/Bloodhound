package org.freedonia.bloodhound.server.auth.sso;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;

class SamlAuthenticationSuccessHandlerTest {

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
