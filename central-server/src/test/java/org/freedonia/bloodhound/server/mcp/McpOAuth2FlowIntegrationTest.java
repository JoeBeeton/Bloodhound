package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.server.orgs.Organization;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Drives the real MCP OAuth2 surface (Dynamic Client Registration, login, consent, token
 * exchange, and a bearer-token call to /mcp) over actual HTTP, through the real filter chains in
 * McpSecurityConfig - not through mocks.
 *
 * <p>This exists because every MCP auth bug fixed in October 2026 (missing {@code
 * scopes_supported} in the RFC 9728 protected-resource metadata, then Spring's default DCR scope
 * validator rejecting the very scope that metadata advertised) was completely invisible to the
 * rest of this package's test suite, which is all {@code @Mock}-based unit/slice tests that never
 * actually route a request through FilterChainProxy. A real client (Claude Code) hit both bugs in
 * production before either was caught here. Real Postgres via Testcontainers, not H2 - Flyway's
 * migrations use Postgres-specific syntax, and the whole point is to exercise the real filter
 * chains Spring Security builds against the real {@code OAuth2ClientRegistrationAuthenticationValidator}/
 * {@code OAuth2AuthorizationServerConfigurer} wiring, not a simplified substitute.
 *
 * <p>Fixed port (not {@code RANDOM_PORT}): the resource-server chain validates the token's {@code
 * aud} claim against {@code bloodhound.mcp.issuer-uri} (see McpSecurityConfig's own javadoc) and
 * that property has to be set before the server starts, which rules out discovering a random port
 * after the fact.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
            "server.port=18443",
            "bloodhound.mcp.issuer-uri=http://localhost:18443",
            // HS256 requires >=256 bits; this is a fixed, non-placeholder test-only value, never
            // used outside this JVM's own ephemeral Testcontainers Postgres.
            "bloodhound.jwt.signing-key=integration-test-signing-key-not-a-real-secret-0123456789"
        })
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class McpOAuth2FlowIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    private static final String BASE_URL = "http://localhost:18443";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @LocalServerPort
    int port;

    @Autowired
    OrganizationRepository organizationRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
            registeredClientRepository;

    private static final String TEST_USER_EMAIL = "mcp-flow-test@freedonia.example";
    private static final String TEST_USER_PASSWORD = "mcp-flow-test-Passw0rd!";

    @BeforeAll
    void seedUser() {
        Organization org = organizationRepository.insert("MCP Flow Test Org", "mcp-flow-test-org");
        userRepository.insertLocalUser(
                org.id(), TEST_USER_EMAIL, "MCP Flow Test User", "ADMIN", passwordEncoder.encode(TEST_USER_PASSWORD));
    }

    @Test
    void protectedResourceMetadataAdvertisesMcpReadScope() throws Exception {
        // Regression test for the first bug in this chain (commit dc77559): without
        // scopes_supported, an MCP client has no way to learn it should request mcp.read at
        // /oauth2/authorize, and every resulting token is scopeless and useless against /mcp.
        HttpClient client = newClient();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create(BASE_URL + "/.well-known/oauth-protected-resource"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode body = MAPPER.readTree(response.body());
        assertThat(body.get("scopes_supported")).isNotNull();
        assertThat(body.get("scopes_supported").toString()).contains("mcp.read");
    }

    @Test
    void dcrAcceptsExplicitMcpReadScope() throws Exception {
        // Regression test for the second bug (commit 555bc23): once scopes_supported above
        // started advertising mcp.read, a spec-following client echoes it back at registration -
        // Spring's DEFAULT_SCOPE_VALIDATOR used to hard-reject any non-empty scope here at all.
        HttpResponse<String> response =
                registerClient(newClient(), "Regression - explicit mcp.read scope", "mcp.read");

        assertThat(response.statusCode()).isEqualTo(201);
        JsonNode body = MAPPER.readTree(response.body());
        assertThat(body.get("scope").asText()).isEqualTo("mcp.read");
    }

    @Test
    void dcrRejectsScopeOtherThanMcpRead() throws Exception {
        // The fix narrows Spring's default validator, it doesn't remove it - DCR must still
        // refuse to register a client under a made-up scope name.
        HttpResponse<String> response = registerClient(newClient(), "Regression - bogus scope", "evil.scope");

        assertThat(response.statusCode()).isEqualTo(400);
        JsonNode body = MAPPER.readTree(response.body());
        assertThat(body.get("error").asText()).isEqualTo("invalid_scope");
    }

    @Test
    void dcrWithOmittedScopeStillDefaultsToMcpRead() throws Exception {
        // The legacy path (RFC 7591's "server decides" default, handled by
        // ConsentRequiringRegisteredClientRepository) must keep working alongside the new one.
        // The registration response itself doesn't echo the server-assigned default back (RFC
        // 7591 doesn't require it to), so this checks the persisted RegisteredClient directly -
        // which is what actually matters: it's what the resource-server chain enforces against.
        HttpResponse<String> response = registerClient(newClient(), "Regression - omitted scope", null);
        assertThat(response.statusCode()).isEqualTo(201);

        String clientId = MAPPER.readTree(response.body()).get("client_id").asText();
        assertThat(registeredClientRepository.findByClientId(clientId).getScopes()).containsExactly("mcp.read");
    }

    @Test
    void mcpRejectsRequestWithNoBearerToken() throws Exception {
        HttpClient client = newClient();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create(BASE_URL + "/mcp"))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json, text/event-stream")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isIn(401, 403);
    }

    @Test
    void fullAuthorizationCodeFlowReachesMcpInitialize() throws Exception {
        HttpClient client = newClient();

        HttpResponse<String> registration =
                registerClient(client, "End-to-end flow test client", "mcp.read");
        assertThat(registration.statusCode()).isEqualTo(201);
        String clientId = MAPPER.readTree(registration.body()).get("client_id").asText();
        String redirectUri = "http://localhost:4321/callback";
        String resource = BASE_URL + "/mcp";

        String codeVerifier = randomUrlSafe(32);
        String codeChallenge = codeChallengeS256(codeVerifier);

        String code = authorizeAndConsent(client, clientId, redirectUri, "mcp.read", resource, codeChallenge);
        assertThat(code).isNotBlank();

        HttpResponse<String> tokenResponse =
                exchangeCodeForToken(client, clientId, redirectUri, code, codeVerifier, resource);
        assertThat(tokenResponse.statusCode()).isEqualTo(200);
        JsonNode tokenBody = MAPPER.readTree(tokenResponse.body());
        assertThat(tokenBody.get("scope").asText()).isEqualTo("mcp.read");
        String accessToken = tokenBody.get("access_token").asText();

        HttpResponse<String> mcpResponse = callMcpInitialize(accessToken);
        assertThat(mcpResponse.statusCode()).isEqualTo(200);
        JsonNode mcpBody = MAPPER.readTree(mcpResponse.body());
        assertThat(mcpBody.at("/result/serverInfo/name").asText()).isEqualTo("bloodhound-mcp-server");
    }

    // --- flow helpers, mirroring a real browser-driven OAuth2 authorization_code + PKCE flow ---

    private HttpResponse<String> registerClient(HttpClient client, String clientName, String scope)
            throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_name", clientName);
        body.put("redirect_uris", java.util.List.of("http://localhost:4321/callback"));
        body.put("grant_types", java.util.List.of("authorization_code"));
        body.put("response_types", java.util.List.of("code"));
        body.put("token_endpoint_auth_method", "none");
        if (scope != null) {
            body.put("scope", scope);
        }
        return client.send(
                HttpRequest.newBuilder(URI.create(BASE_URL + "/oauth2/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(body)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String authorizeAndConsent(
            HttpClient client,
            String clientId,
            String redirectUri,
            String scope,
            String resource,
            String codeChallenge)
            throws Exception {
        String authorizeUrl = BASE_URL + "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256"
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&scope=" + urlEncode(scope)
                + "&resource=" + urlEncode(resource);

        // 1. Unauthenticated -> redirected to /login.
        HttpResponse<String> toLogin = getFollowingNoRedirect(client, authorizeUrl);
        assertThat(toLogin.statusCode()).isEqualTo(302);
        String loginUrl = resolve(authorizeUrl, toLogin.headers().firstValue("Location").orElseThrow());

        // 2. Render the login page, extract its CSRF token.
        HttpResponse<String> loginPage = getFollowingNoRedirect(client, loginUrl);
        assertThat(loginPage.statusCode()).isEqualTo(200);
        String loginCsrf = extractHidden(loginPage.body(), "_csrf");

        // 3. Submit credentials -> redirected back to the originally saved /oauth2/authorize request.
        String loginForm = "username=" + urlEncode(TEST_USER_EMAIL)
                + "&password=" + urlEncode(TEST_USER_PASSWORD)
                + "&_csrf=" + urlEncode(loginCsrf);
        HttpResponse<String> loginResult = client.send(
                HttpRequest.newBuilder(URI.create(loginUrl))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(loginResult.statusCode()).isEqualTo(302);
        String savedRequestUrl = resolve(loginUrl, loginResult.headers().firstValue("Location").orElseThrow());

        // 4. Replay the saved authorize request, now authenticated -> consent required.
        HttpResponse<String> toConsent = getFollowingNoRedirect(client, savedRequestUrl);
        assertThat(toConsent.statusCode()).isEqualTo(302);
        String consentUrl = resolve(savedRequestUrl, toConsent.headers().firstValue("Location").orElseThrow());

        // 5. Render the consent page, extract its CSRF/state/client_id.
        HttpResponse<String> consentPage = getFollowingNoRedirect(client, consentUrl);
        assertThat(consentPage.statusCode()).isEqualTo(200);
        String consentCsrf = extractHidden(consentPage.body(), "_csrf");
        String state = extractHidden(consentPage.body(), "state");

        // 6. Approve consent -> redirected to redirect_uri with the authorization code.
        String consentForm = "_csrf=" + urlEncode(consentCsrf)
                + "&client_id=" + urlEncode(clientId)
                + "&state=" + urlEncode(state)
                + "&scope=" + urlEncode(scope);
        HttpResponse<String> consentResult = client.send(
                HttpRequest.newBuilder(URI.create(BASE_URL + "/oauth2/authorize"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(consentForm))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(consentResult.statusCode()).isEqualTo(302);
        String callback = consentResult.headers().firstValue("Location").orElseThrow();
        return extractQueryParam(callback, "code");
    }

    private HttpResponse<String> exchangeCodeForToken(
            HttpClient client, String clientId, String redirectUri, String code, String codeVerifier, String resource)
            throws Exception {
        String form = "grant_type=authorization_code"
                + "&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&client_id=" + urlEncode(clientId)
                + "&code_verifier=" + urlEncode(codeVerifier)
                + "&resource=" + urlEncode(resource);
        return client.send(
                HttpRequest.newBuilder(URI.create(BASE_URL + "/oauth2/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> callMcpInitialize(String accessToken) throws Exception {
        return newClient()
                .send(
                        HttpRequest.newBuilder(URI.create(BASE_URL + "/mcp"))
                                .header("Authorization", "Bearer " + accessToken)
                                .header("Content-Type", "application/json")
                                .header("Accept", "application/json, text/event-stream")
                                .POST(HttpRequest.BodyPublishers.ofString(
                                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                                                + "\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
                                                + "\"clientInfo\":{\"name\":\"integration-test\",\"version\":\"1.0\"}}}"))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> getFollowingNoRedirect(HttpClient client, String url) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Accept", "text/html")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpClient newClient() {
        return HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    private static String extractHidden(String html, String fieldName) {
        Matcher matcher = Pattern.compile("name=\"" + Pattern.quote(fieldName) + "\"\\s+value=\"([^\"]*)\"")
                .matcher(html);
        if (!matcher.find()) {
            throw new IllegalStateException("hidden field \"" + fieldName + "\" not found in: " + html);
        }
        return matcher.group(1);
    }

    private static String extractQueryParam(String url, String paramName) {
        Matcher matcher = Pattern.compile("[?&]" + paramName + "=([^&]+)").matcher(url);
        if (!matcher.find()) {
            throw new IllegalStateException("query param \"" + paramName + "\" not found in: " + url);
        }
        return java.net.URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8);
    }

    private static String resolve(String base, String location) {
        return URI.create(base).resolve(location).toString();
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String randomUrlSafe(int numBytes) {
        byte[] bytes = new byte[numBytes];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String codeChallengeS256(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
