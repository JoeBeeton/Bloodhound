package org.freedonia.bloodhound.server.auth.sso.dto;

import org.freedonia.bloodhound.server.auth.sso.IdentityProvider;

/**
 * Includes the SP-side metadata (spEntityId/spAcsUrl) the org's IT admin
 * needs to hand to their own IdP - SAML setup is always a two-sided exchange,
 * so the admin UI shows both halves.
 */
public record IdentityProviderConfigResponse(
        String registrationId,
        String idpEntityId,
        String idpSsoUrl,
        String idpX509Cert,
        String emailAttributeName,
        String displayNameAttributeName,
        boolean enabled,
        String spEntityId,
        String spAcsUrl,
        String ssoLoginUrl) {

    public static IdentityProviderConfigResponse from(IdentityProvider idp, String spBaseUrl) {
        String registrationId = idp.registrationId();
        return new IdentityProviderConfigResponse(
                registrationId,
                idp.idpEntityId(),
                idp.idpSsoUrl(),
                idp.idpX509Cert(),
                idp.emailAttributeName(),
                idp.displayNameAttributeName(),
                idp.enabled(),
                spBaseUrl + "/saml2/service-provider-metadata/" + registrationId,
                spBaseUrl + "/login/saml2/sso/" + registrationId,
                spBaseUrl + "/saml2/authenticate/" + registrationId);
    }
}
