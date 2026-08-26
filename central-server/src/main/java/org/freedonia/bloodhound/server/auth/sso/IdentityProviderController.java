package org.freedonia.bloodhound.server.auth.sso;

import jakarta.validation.Valid;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.sso.dto.IdentityProviderConfigRequest;
import org.freedonia.bloodhound.server.auth.sso.dto.IdentityProviderConfigResponse;
import org.freedonia.bloodhound.server.orgs.Organization;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Admin-only per-org SAML configuration. One IdP per org (see V18's
 * UNIQUE(organization_id)) - GET returns either the existing config or, if
 * none exists yet, a template response built purely from the org's slug (so
 * the admin UI can still show the SP metadata - ACS URL/entity ID - to hand
 * to their IdP *before* the IdP's own side is known, since that's usually
 * the first half of a real setup exchange).
 */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/sso")
@PreAuthorize("hasRole('ADMIN')")
public class IdentityProviderController {

    private final IdentityProviderRepository identityProviderRepository;
    private final OrganizationRepository organizationRepository;
    private final String spBaseUrl;

    public IdentityProviderController(
            IdentityProviderRepository identityProviderRepository,
            OrganizationRepository organizationRepository,
            @Value("${bloodhound.saml.sp-base-url}") String spBaseUrl) {
        this.identityProviderRepository = identityProviderRepository;
        this.organizationRepository = organizationRepository;
        this.spBaseUrl = spBaseUrl;
    }

    @GetMapping
    public IdentityProviderConfigResponse get(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return identityProviderRepository
                .findByOrganizationId(orgId)
                .map(idp -> IdentityProviderConfigResponse.from(idp, spBaseUrl))
                .orElseGet(() -> unconfiguredTemplate(orgId));
    }

    @PutMapping
    public IdentityProviderConfigResponse put(
            @PathVariable UUID orgId,
            @Valid @RequestBody IdentityProviderConfigRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        Organization org = organizationRepository.findById(orgId).orElseThrow();
        IdentityProvider saved = identityProviderRepository.upsert(
                orgId,
                org.slug(),
                request.idpEntityId(),
                request.idpSsoUrl(),
                request.idpX509Cert(),
                request.emailAttributeName(),
                request.displayNameAttributeName(),
                request.enabled());
        return IdentityProviderConfigResponse.from(saved, spBaseUrl);
    }

    private IdentityProviderConfigResponse unconfiguredTemplate(UUID orgId) {
        Organization org = organizationRepository.findById(orgId).orElseThrow();
        return new IdentityProviderConfigResponse(
                org.slug(),
                "",
                "",
                "",
                "email",
                null,
                false,
                spBaseUrl + "/saml2/service-provider-metadata/" + org.slug(),
                spBaseUrl + "/login/saml2/sso/" + org.slug(),
                spBaseUrl + "/saml2/authenticate/" + org.slug());
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!principal.organizationId().equals(orgId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "cannot manage SSO config outside your organization");
        }
    }
}
