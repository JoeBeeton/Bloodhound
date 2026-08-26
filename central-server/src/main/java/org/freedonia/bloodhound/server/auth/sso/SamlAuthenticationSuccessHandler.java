package org.freedonia.bloodhound.server.auth.sso;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.freedonia.bloodhound.server.auth.AuthResult;
import org.freedonia.bloodhound.server.auth.AuthenticationService;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
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
        String registrationId = principal.getRelyingPartyRegistrationId();

        IdentityProvider idp = identityProviderRepository
                .findByRegistrationId(registrationId)
                .orElseThrow(() -> new IllegalStateException(
                        "SAML success for unknown registrationId " + registrationId));

        String email = firstAttribute(principal, idp.emailAttributeName())
                .orElseThrow(() -> new IllegalStateException(
                        "SAML assertion from " + registrationId + " has no '" + idp.emailAttributeName()
                                + "' attribute - check the org's email_attribute_name mapping"));
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

    // Package-private (not private) so SamlAuthenticationSuccessHandlerTest can exercise it directly -
    // this is the one genuinely pure piece of this class's logic; everything else touches the DB/HTTP.
    static Optional<String> firstAttribute(Saml2AuthenticatedPrincipal principal, String attributeName) {
        Object value = principal.getFirstAttribute(attributeName);
        return value == null ? Optional.empty() : Optional.of(String.valueOf(value));
    }
}
