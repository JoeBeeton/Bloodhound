package org.freedonia.bloodhound.server.auth.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.auth.sso.dto.IdentityProviderConfigRequest;
import org.freedonia.bloodhound.server.orgs.Organization;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class IdentityProviderControllerTest {

    private final IdentityProviderRepository identityProviderRepository = mock(IdentityProviderRepository.class);
    private final OrganizationRepository organizationRepository = mock(OrganizationRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final IdentityProviderController controller = new IdentityProviderController(
            identityProviderRepository, organizationRepository, auditLogRepository, "https://sp.example.com");

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    // Same real certificate DbRelyingPartyRegistrationRepositoryTest captured from a live
    // kristophjunge/test-saml-idp container - put() now eagerly parses this with that exact
    // class's own parseCertificate, so any test exercising a successful save needs a genuinely
    // parseable cert, not a placeholder string like the old "cert-data"/"super-secret-cert-material".
    private static final String REAL_CERT_BASE64 =
            "MIIDXTCCAkWgAwIBAgIJALmVVuDWu4NYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYxMjMxMTQzNDQ3WhcNNDgwNjI1MTQzNDQ3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUCFozgNb1h1M0jzNRSCjhOBnR+uVbVpaWfXYIR+AhWDdEe5ryY+CgavOg8bfLybyzFdehlYdDRgkedEB/GjG8aJw06l0qF4jDOAw0kEygWCu2mcH7XOxRt+YAH3TVHa/Hu1W3WjzkobqqqLQ8gkKWWM27fOgAZ6GieaJBN6VBSMMcPey3HWLBmc+TYJmv1dbaO2jHhKh8pfKw0W12VM8P1PIO8gv4Phu/uuJYieBWKixBEyy0lHjyixYFCR12xdh4CA47q958ZRGnnDUGFVE1QhgRacJCOZ9bd5t9mr8KLaVBYTCJo5ERE8jymab5dPqe5qKfJsCZiqWglbjUo9twIDAQABo1AwTjAdBgNVHQ4EFgQUxpuwcs/CYQOyui+r1G+3KxBNhxkwHwYDVR0jBBgwFoAUxpuwcs/CYQOyui+r1G+3KxBNhxkwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAiWUKs/2x/viNCKi3Y6blEuCtAGhzOOZ9EjrvJ8+COH3Rag3tVBWrcBZ3/uhhPq5gy9lqw4OkvEws99/5jFsX1FJ6MKBgqfuy7yh5s1YfM0ANHYczMmYpZeAcQf2CGAaVfwTTfSlzNLsF2lW/ly7yapFzlYSJLGoVE+OHEu8g5SlNACUEfkXw+5Eghh+KzlIN7R6Q7r2ixWNFBC/jWf7NKUfJyX8qIG5md1YUeT6GBW9Bm2/1/RiO24JTaYlfLdKK9TYb8sG5B+OLab2DImG99CJ25RkAcSobWNF5zD0O6lgOo3cEdB/ksCq3hmtlC/DlLZ/D8CJ+7VuZnS1rR2naQ==";

    private Organization org() {
        return new Organization(orgId, "Org", "org-slug", Instant.now(), true);
    }

    private IdentityProvider saved(boolean enabled) {
        return new IdentityProvider(
                UUID.randomUUID(), orgId, "org-slug", "idp-entity", "https://idp.example.com/sso", REAL_CERT_BASE64,
                "email", "name", enabled, Instant.now(), Instant.now());
    }

    @Test
    void put_differentOrg_forbidden() {
        UUID otherOrgId = UUID.randomUUID();

        assertThatThrownBy(() -> controller.put(
                        otherOrgId,
                        new IdentityProviderConfigRequest(
                                "e", "https://idp.example.com/sso", REAL_CERT_BASE64, "email", null, true),
                        admin))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void put_recordsAuditEntry_reflectingTheResultingEnabledState() {
        // A security review found this - the config controlling how every user in the org
        // authenticates, once SAML SSO is enabled - had no audit trail at all, despite being the
        // single most security-sensitive unaudited write in the app.
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org()));
        when(identityProviderRepository.upsert(
                        orgId,
                        "org-slug",
                        "idp-entity",
                        "https://idp.example.com/sso",
                        REAL_CERT_BASE64,
                        "email",
                        null,
                        true))
                .thenReturn(saved(true));

        controller.put(
                orgId,
                new IdentityProviderConfigRequest(
                        "idp-entity", "https://idp.example.com/sso", REAL_CERT_BASE64, "email", null, true),
                admin);

        verify(auditLogRepository).record(
                orgId, admin.userId(), admin.email(), "SSO_CONFIG_SAVED", "ORGANIZATION", orgId.toString(), "enabled=true");
    }

    @Test
    void put_neverLogsTheX509CertOrIdpUrls() {
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org()));
        when(identityProviderRepository.upsert(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(saved(false));

        controller.put(
                orgId,
                new IdentityProviderConfigRequest(
                        "idp-entity", "https://idp.example.com/sso", REAL_CERT_BASE64, "email", null, false),
                admin);

        org.mockito.ArgumentCaptor<String> detailCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(auditLogRepository).record(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                detailCaptor.capture());
        assertThat(detailCaptor.getValue()).doesNotContain(REAL_CERT_BASE64, "idp.example.com");
    }

    @Test
    void put_unparseableCert_rejectedWithAClearMessage_neverStored() {
        // Confirmed live (and via DbRelyingPartyRegistrationRepositoryTest#rejectsGarbage) that
        // "not a certificate" isn't valid PEM/base64-DER - previously this was accepted anyway
        // (identity_providers.idp_x509_cert is unbounded TEXT with no format check) and only blew
        // up as a runtime IllegalStateException the next time someone tried to actually log in.
        ResponseEntity<?> response = controller.put(
                orgId,
                new IdentityProviderConfigRequest(
                        "idp-entity", "https://idp.example.com/sso", "not a certificate", "email", null, true),
                admin);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(((IdentityProviderController.ErrorMessageResponse) response.getBody()).message())
                .contains("Invalid X.509 certificate");
        verify(identityProviderRepository, never())
                .upsert(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.anyBoolean());
        verify(auditLogRepository, never())
                .record(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any());
    }
}
