package org.freedonia.bloodhound.server.auth.sso;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.freedonia.bloodhound.server.auth.AuthResult;
import org.freedonia.bloodhound.server.auth.AuthenticationService;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Runs once a SAML assertion has been validated. JIT-provisions the user,
 * mints real tokens via the same AuthenticationService.issueTokens local
 * login uses, then redirects the browser to webui with only a short-lived
 * one-time handoff code (see SsoHandoffCodeRepository) - never the real
 * tokens themselves, which would otherwise land in browser history and
 * server access logs.
 */
@Component
public class SamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(SamlAuthenticationSuccessHandler.class);

    private final IdentityProviderRepository identityProviderRepository;
    private final UserRepository userRepository;
    private final AuthenticationService authenticationService;
    private final SsoHandoffCodeRepository handoffCodeRepository;
    private final String webuiCallbackUrl;

    public SamlAuthenticationSuccessHandler(
            IdentityProviderRepository identityProviderRepository,
            UserRepository userRepository,
            AuthenticationService authenticationService,
            SsoHandoffCodeRepository handoffCodeRepository,
            @Value("${bloodhound.saml.webui-callback-url}") String webuiCallbackUrl) {
        this.identityProviderRepository = identityProviderRepository;
        this.userRepository = userRepository;
        this.authenticationService = authenticationService;
        this.handoffCodeRepository = handoffCodeRepository;
        this.webuiCallbackUrl = webuiCallbackUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        Saml2Authentication samlAuth = (Saml2Authentication) authentication;
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) samlAuth.getPrincipal();
        // A security review verifying a filter-chain-ordering fix elsewhere (McpSecurityConfig)
        // found SSO was ALSO broken independently of that, for a second, unrelated reason: this
        // app's Spring Boot 3->4 migration moved from OpenSaml4AuthenticationProvider to
        // OpenSaml5AuthenticationProvider, which stopped populating registrationId onto the
        // *principal* (DefaultSaml2AuthenticatedPrincipal.getRelyingPartyRegistrationId() always
        // returned null in practice - confirmed live, and confirmed via the library's own
        // bytecode that nothing ever calls its setter) and instead carries it on the actual
        // Saml2AssertionAuthentication object OpenSaml5AuthenticationProvider now constructs.
        // Every real SAML login has been hitting the "unknown identity provider" error branch
        // below since that migration - never caught because the filter-chain bug meant no
        // assertion had reached this handler at all until just now, when fixing the first bug
        // exposed the second one sitting right behind it.
        String registrationId = authentication instanceof Saml2AssertionAuthentication assertionAuth
                ? assertionAuth.getRelyingPartyRegistrationId()
                : principal.getRelyingPartyRegistrationId();

        // Both of these were previously thrown as an unhandled IllegalStateException - a security/
        // UX review found that meant an admin mid-way through setting up SSO (the single most
        // likely time to actually hit either of these: a stale registrationId from a half-finished
        // config change, or - the common real mistake - an email_attribute_name that doesn't match
        // what the IdP's assertion actually sends) got a raw, unactionable 500 with no indication
        // of what to fix, instead of ever reaching the SPA's own error UI (SsoCallbackPage.tsx
        // already renders a clean message for a missing/invalid handoff code - these are the same
        // kind of "the SSO flow didn't complete" outcome, just detected earlier in the process).
        Optional<IdentityProvider> idpLookup = identityProviderRepository.findByRegistrationId(registrationId);
        if (idpLookup.isEmpty()) {
            log.warn("SAML success for unknown registrationId {}", registrationId);
            redirectWithError(response, "SSO configuration error: unrecognized identity provider. Contact your administrator.");
            return;
        }
        IdentityProvider idp = idpLookup.get();

        Optional<String> emailLookup = firstAttribute(principal, idp.emailAttributeName());
        if (emailLookup.isEmpty()) {
            log.warn(
                    "SAML assertion from {} has no '{}' attribute - check the org's email_attribute_name mapping",
                    registrationId,
                    idp.emailAttributeName());
            redirectWithError(
                    response,
                    "SSO configuration error: the identity provider's response is missing the configured email"
                            + " attribute. Contact your administrator to check the SSO email attribute mapping.");
            return;
        }
        String email = emailLookup.get();
        String displayName = idp.displayNameAttributeName() != null
                ? firstAttribute(principal, idp.displayNameAttributeName()).orElse(email)
                : email;
        String externalId = principal.getName(); // the assertion's NameID

        User user = userRepository.findOrCreateSamlUser(idp.organizationId(), externalId, email, displayName);
        if (!"ACTIVE".equals(user.status())) {
            log.warn("SAML login for disabled user {} (org {}) rejected", user.email(), idp.organizationId());
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "account disabled");
            return;
        }
        userRepository.touchLastLogin(user.id());

        AuthResult tokens = authenticationService.issueTokens(user);
        String code = handoffCodeRepository.create(user.id(), tokens.accessToken(), tokens.expiresIn(), tokens.refreshToken());

        response.sendRedirect(webuiCallbackUrl + "?code=" + code);
    }

    /** Same handoff destination as a successful login, an "error" param instead of "code" - see SsoCallbackPage.tsx. */
    private void redirectWithError(HttpServletResponse response, String message) throws IOException {
        response.sendRedirect(webuiCallbackUrl + "?error=" + URLEncoder.encode(message, StandardCharsets.UTF_8));
    }

    // Package-private (not private) so SamlAuthenticationSuccessHandlerTest can exercise it directly -
    // this is the one genuinely pure piece of this class's logic; everything else touches the DB/HTTP.
    static Optional<String> firstAttribute(Saml2AuthenticatedPrincipal principal, String attributeName) {
        Object value = principal.getFirstAttribute(attributeName);
        return value == null ? Optional.empty() : Optional.of(String.valueOf(value));
    }
}
