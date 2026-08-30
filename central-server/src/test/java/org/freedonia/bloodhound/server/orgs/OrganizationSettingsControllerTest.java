package org.freedonia.bloodhound.server.orgs;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.orgs.OrganizationSettingsController.OrgSettingsResponse;
import org.freedonia.bloodhound.server.orgs.OrganizationSettingsController.UpdateOrgSettingsRequest;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class OrganizationSettingsControllerTest {

    private final OrganizationRepository organizationRepository = mock(OrganizationRepository.class);
    private final OrganizationSettingsController controller = new OrganizationSettingsController(organizationRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID otherOrgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private Organization org(boolean mcpEnabled) {
        return new Organization(orgId, "Org", "org-slug", Instant.now(), mcpEnabled);
    }

    @Test
    void get_differentOrg_notFound() {
        assertThatThrownBy(() -> controller.get(otherOrgId, admin)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_ownOrg_returnsCurrentValue() {
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org(true)));

        OrgSettingsResponse result = controller.get(orgId, admin);

        assertThat(result.mcpEnabled()).isTrue();
    }

    @Test
    void update_differentOrg_notFound_neverWrites() {
        assertThatThrownBy(() -> controller.update(otherOrgId, admin, new UpdateOrgSettingsRequest(false)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void update_setsFlag_returnsUpdatedValue() {
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org(true))).thenReturn(Optional.of(org(false)));

        OrgSettingsResponse result = controller.update(orgId, admin, new UpdateOrgSettingsRequest(false));

        verify(organizationRepository).setMcpEnabled(orgId, false);
        assertThat(result.mcpEnabled()).isFalse();
    }
}
