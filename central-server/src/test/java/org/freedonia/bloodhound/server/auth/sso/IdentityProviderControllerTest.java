package org.freedonia.bloodhound.server.auth.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
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
import org.springframework.web.server.ResponseStatusException;

class IdentityProviderControllerTest {

    private final IdentityProviderRepository identityProviderRepository = mock(IdentityProviderRepository.class);
    private final OrganizationRepository organizationRepository = mock(OrganizationRepository.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final IdentityProviderController controller = new IdentityProviderController(
            identityProviderRepository, organizationRepository, auditLogRepository, "https://sp.example.com");

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private Organization org() {
        return new Organization(orgId, "Org", "org-slug", Instant.now(), true);
    }

    private IdentityProvider saved(boolean enabled) {
        return new IdentityProvider(
                UUID.randomUUID(), orgId, "org-slug", "idp-entity", "https://idp.example.com/sso", "cert-data",
                "email", "name", enabled, Instant.now(), Instant.now());
    }

    @Test
    void put_differentOrg_forbidden() {
        UUID otherOrgId = UUID.randomUUID();

        assertThatThrownBy(() -> controller.put(
                        otherOrgId,
                        new IdentityProviderConfigRequest("e", "https://idp", "cert", "email", null, true),
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
                        orgId, "org-slug", "idp-entity", "https://idp.example.com/sso", "cert-data", "email", null, true))
                .thenReturn(saved(true));

        controller.put(
                orgId,
                new IdentityProviderConfigRequest(
                        "idp-entity", "https://idp.example.com/sso", "cert-data", "email", null, true),
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
                        "idp-entity", "https://idp.example.com/sso", "super-secret-cert-material", "email", null, false),
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
        assertThat(detailCaptor.getValue()).doesNotContain("super-secret-cert-material", "idp.example.com");
    }
}
