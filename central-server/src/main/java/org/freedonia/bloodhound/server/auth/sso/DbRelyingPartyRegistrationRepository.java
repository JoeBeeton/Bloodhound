package org.freedonia.bloodhound.server.auth.sso;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

/**
 * Multi-tenant SAML config: builds a RelyingPartyRegistration on demand from
 * the identity_providers table (Spring Security's default repository is
 * static/in-memory, which can't represent "whichever orgs have SAML enabled
 * right now"). Only enabled=true rows resolve - a disabled/never-configured
 * org's registrationId simply isn't found, same as it never existed.
 *
 * <p>SP base URL is explicit config (bloodhound.saml.sp-base-url), not
 * Spring's default request-derived {baseUrl} templating - central-server is
 * reached at different hostnames depending on caller (the container network's
 * "central-server" vs. the browser's published host port), and the ACS URL
 * embedded in the AuthnRequest must be the one the *browser* will actually
 * POST the SAML response back to, not whichever happened to make the
 * /saml2/authenticate/{id} request server-side.
 *
 * <p>SP requests are unsigned (wantAuthnRequestsSigned(false), no SP signing
 * credential configured) - the simplest viable config that still validates
 * incoming assertions against the IdP's certificate (that part is not
 * optional). Many real IdP integrations work fine with unsigned AuthnRequests;
 * SP-side request signing is a reasonable future hardening step, not required
 * for a working flow.
 */
@Component
public class DbRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private final IdentityProviderRepository identityProviderRepository;
    private final String spBaseUrl;

    public DbRelyingPartyRegistrationRepository(
            IdentityProviderRepository identityProviderRepository,
            @Value("${bloodhound.saml.sp-base-url}") String spBaseUrl) {
        this.identityProviderRepository = identityProviderRepository;
        this.spBaseUrl = spBaseUrl;
    }

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        IdentityProvider idp = identityProviderRepository
                .findByRegistrationId(registrationId)
                .filter(IdentityProvider::enabled)
                .orElse(null);
        if (idp == null) {
            return null;
        }
        Saml2X509Credential verificationCredential =
                Saml2X509Credential.verification(parseCertificate(idp.idpX509Cert()));

        return RelyingPartyRegistration.withRegistrationId(registrationId)
                .entityId(spBaseUrl + "/saml2/service-provider-metadata/" + registrationId)
                .assertionConsumerServiceLocation(spBaseUrl + "/login/saml2/sso/" + registrationId)
                .assertingPartyMetadata(party -> party.entityId(idp.idpEntityId())
                        .singleSignOnServiceLocation(idp.idpSsoUrl())
                        .wantAuthnRequestsSigned(false)
                        .verificationX509Credentials(c -> c.add(verificationCredential)))
                .build();
    }

    // Package-private (not private) so DbRelyingPartyRegistrationRepositoryTest can exercise it
    // directly against a real captured IdP certificate, without needing a Spring context.
    static X509Certificate parseCertificate(String pemOrBase64) {
        try {
            String normalized = pemOrBase64.contains("BEGIN CERTIFICATE")
                    ? pemOrBase64
                    : "-----BEGIN CERTIFICATE-----\n" + pemOrBase64 + "\n-----END CERTIFICATE-----";
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw new IllegalStateException("Invalid IdP X.509 certificate", e);
        }
    }
}
