package org.freedonia.bloodhound.server.auth.sso.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.hibernate.validator.constraints.URL;

/**
 * A security review found this had zero format/length validation on any field, including the
 * X.509 cert - a malformed value here was silently accepted by PUT (identity_providers' own
 * columns are all unbounded TEXT) and only ever surfaced as a runtime IllegalStateException the
 * next time someone actually tried to log in via SAML (see
 * DbRelyingPartyRegistrationRepository#parseCertificate, called lazily at login time, not save
 * time). IdentityProviderController#put now also eagerly re-parses the cert with that exact same
 * method, so a bad cert is rejected immediately with a clear message, not discovered later by a
 * locked-out end user.
 *
 * <p>idpEntityId is deliberately not {@code @URL} - the SAML spec allows any URI as an entity ID,
 * including URN form (e.g. {@code urn:mace:...}), which real IdPs use. idpSsoUrl genuinely must
 * be an HTTP(S) endpoint (it's the redirect-binding location a browser is sent to), so that one
 * gets the format check.
 */
public record IdentityProviderConfigRequest(
        @NotBlank @Size(max = 1000) String idpEntityId,
        @NotBlank @URL @Size(max = 2000) String idpSsoUrl,
        @NotBlank @Size(max = 32000) String idpX509Cert,
        @NotBlank @Size(max = 500) String emailAttributeName,
        @Size(max = 500) String displayNameAttributeName,
        boolean enabled) {}
