package org.freedonia.bloodhound.server.mcp;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.AuthenticatedUserPrincipal;
import org.freedonia.bloodhound.server.orgs.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Infrastructure beans Spring Authorization Server needs, backing the OAuth2-authenticated MCP
 * server (see McpSecurityConfig for the actual filter chains, McpTokenCustomizer for the org/role
 * claims added to every issued token). JDBC-backed (not in-memory) for the registered-client and
 * authorization tables - see V40__oauth2_authorization_server.sql for the schema, adapted from
 * Spring Authorization Server's own default JDBC schema (Apache-2.0).
 */
@Configuration
public class McpAuthorizationServerBeans {

    private static final Logger log = LoggerFactory.getLogger(McpAuthorizationServerBeans.class);

    /**
     * Wrapped, not the plain {@link JdbcRegisteredClientRepository}, so every registered client -
     * however it gets created (Dynamic Client Registration, or any future manual/admin
     * registration path) - is forced to require user consent. Spring Authorization Server's own
     * default for {@code ClientSettings.requireAuthorizationConsent} is {@code false} (confirmed
     * live via {@code ClientSettings.builder().build().isRequireAuthorizationConsent()}), and nothing
     * else in this app was overriding it - a security review found that a real authorization_code
     * request against a client left on that default redirects straight back to its redirect_uri
     * with a valid code, with zero consent screen ever shown, for ANY already-logged-in user.
     * Concretely: an attacker registers a client with a redirect_uri they control, sends a
     * Bloodhound user a single link to /oauth2/authorize?client_id=<theirs>&..., and receives a
     * working access token bearing that user's org/role claims - no XSS, no password, one click.
     * PKCE does not stop this: the attacker holds their own code_verifier, since they ARE the
     * client. Enforcing consent here, at the single save() choke point every registration path
     * goes through, closes it regardless of how a client comes to exist - a real consent UI
     * (currently Spring's plain default page) can still be improved later, but skipping it
     * entirely must never be possible.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
        return new ConsentRequiringRegisteredClientRepository(new JdbcRegisteredClientRepository(jdbc));
    }

    /**
     * Deliberately builds its own ObjectMapper rather than reusing the app's regular {@code
     * ObjectMapper} bean (JacksonConfig's Jackson-2 compatibility bean) - the {@code attributes}
     * column stores polymorphic Spring Security types (e.g. the original OAuth2AuthorizationRequest
     * for the authorization_code flow), which need the library's own Jackson modules registered to
     * deserialize back to their real type rather than a generic LinkedHashMap. Confirmed live: with
     * the app's plain ObjectMapper, the very first authorization_code token exchange 500'd with
     * {@code ClassCastException: LinkedHashMap cannot be cast to OAuth2AuthorizationRequest} - this
     * is Spring Authorization Server's own documented pattern for JDBC-backed authorization storage.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbc, RegisteredClientRepository registeredClientRepository) {
        ObjectMapper oauth2ObjectMapper = new ObjectMapper();
        oauth2ObjectMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        oauth2ObjectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        // AuthenticatedUserPrincipal (this app's own UserDetails implementation, the Authentication
        // principal formLogin produces) isn't a Spring-Security-recognized type, so the security
        // modules' deserialization allowlist rejects it by default - Spring's own documented fix
        // for a custom UserDetails type is a Mixin (see AuthenticatedUserPrincipalMixin below).
        oauth2ObjectMapper.addMixIn(AuthenticatedUserPrincipal.class, AuthenticatedUserPrincipalMixin.class);
        // A security review found that, without this, the full User record - including its
        // bcrypt passwordHash - gets serialized whole into this table's attributes column for
        // every authorization (confirmed live via a direct DB dump: the real hash was sitting in
        // plaintext JSON). Nothing on the MCP path ever reads passwordHash back out (only
        // id/organizationId/role, see McpTokenCustomizer) - excluding it from serialization here
        // stops it from being persisted at all, rather than accepting the wider blast radius of a
        // secondary table holding live credential material it has no reason to hold.
        oauth2ObjectMapper.addMixIn(User.class, UserAttributeMixin.class);

        JdbcOAuth2AuthorizationService service = new JdbcOAuth2AuthorizationService(jdbc, registeredClientRepository);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        rowMapper.setObjectMapper(oauth2ObjectMapper);
        service.setAuthorizationRowMapper(rowMapper);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(oauth2ObjectMapper);
        service.setAuthorizationParametersMapper(parametersMapper);
        return service;
    }

    /**
     * In-memory, not JDBC-backed: consent decisions here are Spring's plain default consent
     * screen only (see registeredClientRepository above - every client now genuinely requires
     * consent, unlike this comment's own earlier, since-fixed claim that it was skipped
     * entirely), and losing them across a restart just means re-approving on next use, not a
     * security-relevant loss - not worth a table that would otherwise need its own retention/
     * cleanup story.
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${bloodhound.mcp.issuer-uri}") String issuerUri) {
        return AuthorizationServerSettings.builder().issuer(issuerUri).build();
    }

    /**
     * Ephemeral RSA keypair, freshly generated every JVM startup - the simplest thing that works
     * for a first version. The real, known cost: restarting central-server invalidates every
     * previously-issued MCP access/refresh token (the resource-server chain can no longer verify
     * their signature against a key it no longer has), forcing every connected MCP client to
     * re-authenticate. A persistent, operator-configured keypair (mirroring how JWT_SIGNING_KEY
     * already works for the user-session JWT system) is a reasonable follow-up once this is
     * proven end-to-end, not required to ship a working v1.
     *
     * <p>A single shared bean (not generated separately per consumer) - {@link #jwkSource} (token
     * signing, authorization server side) and {@link McpSecurityConfig}'s {@code jwtDecoder} bean
     * (token verification, resource server side) both derive from this exact keypair, since this
     * one app is both the issuer and the sole verifier of its own MCP tokens.
     */
    @Bean
    public KeyPair mcpSigningKeyPair() {
        log.warn(
                "MCP OAuth2 signing key is ephemeral (freshly generated this JVM startup) - every "
                        + "previously-issued MCP token is invalidated by a restart. Fine for now; a persistent "
                        + "configured keypair is a reasonable follow-up before relying on long-lived MCP sessions.");
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key generation failed - JVM has no RSA provider", e);
        }
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair mcpSigningKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) mcpSigningKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) mcpSigningKeyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Built directly from the local public key rather than letting the resource-server chain
     * derive it via issuer-based OIDC discovery (the library's default when only an issuer URI is
     * given) - this app is simultaneously the authorization server AND the resource server, so an
     * issuer-based decoder would have to fetch {@code <issuer>/.well-known/openid-configuration}
     * from itself over HTTP during Spring context startup (SecurityFilterChain beans are built
     * before Tomcat is accepting connections), which always fails with connection-refused. Handing
     * the decoder the key directly sidesteps that self-fetch entirely - see McpSecurityConfig.
     */
    @Bean
    public JwtDecoder mcpJwtDecoder(KeyPair mcpSigningKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) mcpSigningKeyPair.getPublic();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    /**
     * Field-visibility (not getter/setter) since AuthenticatedUserPrincipal exposes its one field
     * via a record-style {@code user()} accessor, not a JavaBean {@code getUser()} - simplest to
     * just let Jackson read/write the private field directly rather than adding a bean-style
     * getter to a class whose real job is being a UserDetails wrapper, not a Jackson DTO.
     *
     * <p>Getter/setter auto-detection is explicitly turned OFF (not just left at field-only): the
     * UserDetails interface's own derived methods (getAuthorities/getPassword/isEnabled/etc.) would
     * otherwise still be auto-detected as bean properties on top of the "user" field, and
     * getAuthorities() in particular - a getter-only, polymorphically-typed
     * Collection&lt;GrantedAuthority&gt; - fails deserialization outright ("no way to handle typed
     * deser with setterless yet", confirmed live). None of those are needed on round-trip: the
     * "user" field alone reconstructs everything the real getters derive from it.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonAutoDetect(
            fieldVisibility = JsonAutoDetect.Visibility.ANY,
            getterVisibility = JsonAutoDetect.Visibility.NONE,
            isGetterVisibility = JsonAutoDetect.Visibility.NONE,
            setterVisibility = JsonAutoDetect.Visibility.NONE)
    abstract static class AuthenticatedUserPrincipalMixin {
        @JsonCreator
        AuthenticatedUserPrincipalMixin(@JsonProperty("user") User user) {}
    }

    /**
     * Excludes passwordHash from serialization - see the comment on {@link
     * #authorizationService}. Records deserialize missing properties as null for their
     * constructor parameter (Jackson does not require every component to be present), and nothing
     * on the MCP path ever reads passwordHash back out, so reconstructing a User with it null here
     * is safe.
     */
    @JsonIgnoreProperties({"passwordHash"})
    abstract static class UserAttributeMixin {}
}
