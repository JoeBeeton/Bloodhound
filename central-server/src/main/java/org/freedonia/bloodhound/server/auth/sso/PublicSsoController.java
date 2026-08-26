package org.freedonia.bloodhound.server.auth.sso;

import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unauthenticated by necessity - the login page needs to know whether an org
 * has SSO enabled (and where to send the browser) before the user has any
 * credentials at all. Falls under /api/v1/** normally, so explicitly added
 * to SecurityConfig's permitAll list alongside /api/v1/auth/**. Returns only
 * a boolean + a URL - no IdP configuration detail (that stays admin-only via
 * IdentityProviderController).
 */
@RestController
@RequestMapping("/api/v1/public/sso")
public class PublicSsoController {

    public record SsoLookupResponse(boolean enabled, String ssoLoginUrl) {}

    private final OrganizationRepository organizationRepository;
    private final IdentityProviderRepository identityProviderRepository;
    private final String spBaseUrl;

    public PublicSsoController(
            OrganizationRepository organizationRepository,
            IdentityProviderRepository identityProviderRepository,
            @Value("${bloodhound.saml.sp-base-url}") String spBaseUrl) {
        this.organizationRepository = organizationRepository;
        this.identityProviderRepository = identityProviderRepository;
        this.spBaseUrl = spBaseUrl;
    }

    @GetMapping("/{orgSlug}")
    public SsoLookupResponse lookup(@PathVariable String orgSlug) {
        var org = organizationRepository.findBySlug(orgSlug).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        boolean enabled = identityProviderRepository
                .findByOrganizationId(org.id())
                .map(IdentityProvider::enabled)
                .orElse(false);
        return new SsoLookupResponse(enabled, spBaseUrl + "/saml2/authenticate/" + orgSlug);
    }
}
