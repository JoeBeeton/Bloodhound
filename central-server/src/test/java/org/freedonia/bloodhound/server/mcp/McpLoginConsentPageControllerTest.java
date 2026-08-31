package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

class McpLoginConsentPageControllerTest {

    private final RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
    private final McpLoginConsentPageController controller =
            new McpLoginConsentPageController(registeredClientRepository);

    private HttpServletRequest requestWithCsrf() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        CsrfToken csrf = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test-csrf-token-value");
        when(request.getAttribute(CsrfToken.class.getName())).thenReturn(csrf);
        return request;
    }

    private RegisteredClient client(String id, String name) {
        return RegisteredClient.withId(id)
                .clientId(id)
                .clientName(name)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.com/callback")
                .scope("mcp.read")
                .build();
    }

    @Test
    void loginPage_includesCsrfTokenAndNoErrorBanner_whenNoErrorParam() {
        var response = controller.login(null, requestWithCsrf());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("name=\"_csrf\" value=\"test-csrf-token-value\"");
        assertThat(response.getBody()).doesNotContain("Incorrect email or password");
    }

    @Test
    void loginPage_showsErrorBanner_whenErrorParamPresent() {
        var response = controller.login("", requestWithCsrf());

        assertThat(response.getBody()).contains("Incorrect email or password");
    }

    @Test
    void loginPage_setsCspAndNoStoreCacheControl() {
        var response = controller.login(null, requestWithCsrf());

        assertThat(response.getHeaders().getFirst("Content-Security-Policy")).contains("script-src 'none'");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void consentPage_showsClientNameAndAccountAndScopeCheckbox() {
        when(registeredClientRepository.findByClientId("client-1")).thenReturn(client("id-1", "Claude Desktop"));
        var principal = new TestingAuthenticationToken("user@example.com", null);

        var response = controller.consent("client-1", "mcp.read", "state-abc", principal, requestWithCsrf());

        assertThat(response.getBody()).contains("Claude Desktop");
        assertThat(response.getBody()).contains("user@example.com");
        assertThat(response.getBody())
                .contains("<input type=\"checkbox\" id=\"scope-mcp.read\" name=\"scope\" value=\"mcp.read\" checked>");
        assertThat(response.getBody()).contains("value=\"state-abc\"");
        assertThat(response.getBody()).contains("value=\"client-1\"");
    }

    @Test
    void consentPage_escapesAttackerControlledClientName() {
        // Dynamic Client Registration accepts an arbitrary client_name with no content
        // restriction (see ConsentRequiringRegisteredClientRepository's own length-cap comment) -
        // this is the exact regression this page must never reintroduce now that a DCR-registered
        // client can genuinely reach the consent screen (the scope-granting fix in that same
        // class is what made this reachable at all).
        when(registeredClientRepository.findByClientId("client-1"))
                .thenReturn(client("id-1", "<script>alert(1)</script>"));
        var principal = new TestingAuthenticationToken("user@example.com", null);

        var response = controller.consent("client-1", "mcp.read", "state-abc", principal, requestWithCsrf());

        assertThat(response.getBody()).doesNotContain("<script>alert(1)</script>");
        assertThat(response.getBody()).contains("&lt;script&gt;");
    }

    @Test
    void consentPage_fallsBackToClientId_whenClientNotFound() {
        when(registeredClientRepository.findByClientId("unknown-client")).thenReturn(null);
        var principal = new TestingAuthenticationToken("user@example.com", null);

        var response = controller.consent("unknown-client", "mcp.read", "state-abc", principal, requestWithCsrf());

        assertThat(response.getBody()).contains("unknown-client");
    }

    @Test
    void consentPage_rendersOneCheckboxPerRequestedScope() {
        when(registeredClientRepository.findByClientId("client-1")).thenReturn(client("id-1", "Claude Desktop"));
        var principal = new TestingAuthenticationToken("user@example.com", null);

        var response = controller.consent("client-1", "mcp.read other.scope", "state-abc", principal, requestWithCsrf());

        assertThat(response.getBody()).contains("value=\"mcp.read\"");
        assertThat(response.getBody()).contains("value=\"other.scope\"");
    }
}
