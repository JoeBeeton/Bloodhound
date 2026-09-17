package org.freedonia.bloodhound.server.portfolio;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.portfolio.dto.AddPortfolioMemberRequest;
import org.freedonia.bloodhound.server.portfolio.dto.CreatePortfolioRequest;
import org.freedonia.bloodhound.server.portfolio.dto.PortfolioDetailResponse;
import org.freedonia.bloodhound.server.portfolio.dto.PortfolioSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class PortfolioControllerTest {

    private final PortfolioRepository portfolioRepository = mock(PortfolioRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final PortfolioService portfolioService = mock(PortfolioService.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final PortfolioController controller =
            new PortfolioController(portfolioRepository, targetRepository, portfolioService, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID portfolioId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final JwtPrincipal analyst = new JwtPrincipal(UUID.randomUUID(), orgId, "ANALYST", "analyst@example.com");
    private final JwtPrincipal viewer = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "viewer@example.com");

    private Portfolio portfolio() {
        return new Portfolio(portfolioId, orgId, "UK Credit Brands", Instant.now());
    }

    private Target target() {
        return new Target(targetId, orgId, "example.co.uk", "OWN", "AUTHORIZED", 3600, Instant.now(), true, Instant.now(), null);
    }

    private PortfolioDetail emptyDetail() {
        return new PortfolioDetail(portfolio(), null, null, List.of(), List.of(), List.of());
    }

    @Test
    void get_portfolioInAnotherOrg_notFound() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.get(portfolioId, viewer)).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void get_ownedPortfolio_returnsDetail() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio()));
        when(portfolioService.computeDetail(any())).thenReturn(emptyDetail());

        PortfolioDetailResponse response = controller.get(portfolioId, viewer);

        assertThat(response.name()).isEqualTo("UK Credit Brands");
    }

    @Test
    void list_returnsSummaryPerPortfolio() {
        when(portfolioRepository.findByOrganization(orgId)).thenReturn(List.of(portfolio()));
        when(portfolioService.computeDetail(any())).thenReturn(emptyDetail());

        List<PortfolioSummary> result = controller.list(viewer);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("UK Credit Brands");
    }

    @Test
    void create_viewerRole_forbidden() {
        assertThatThrownBy(() -> controller.create(new CreatePortfolioRequest("x"), viewer))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void create_analystRole_createsAndAudits() {
        when(portfolioRepository.insert(orgId, "UK Credit Brands")).thenReturn(portfolio());
        when(portfolioService.computeDetail(any())).thenReturn(emptyDetail());

        ResponseEntity<PortfolioSummary> response =
                controller.create(new CreatePortfolioRequest("UK Credit Brands"), analyst);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        verify(auditLogRepository)
                .record(eq(orgId), any(), any(), eq("PORTFOLIO_CREATED"), eq("PORTFOLIO"), any(), any());
    }

    @Test
    void addMember_targetInAnotherOrg_notFound() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio()));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.addMember(portfolioId, new AddPortfolioMemberRequest(targetId), analyst))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void addMember_ownedTargetAndPortfolio_movesTargetIn() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio()));
        when(targetRepository.findByIdAndOrganization(targetId, orgId)).thenReturn(Optional.of(target()));
        when(portfolioService.computeDetail(any())).thenReturn(emptyDetail());

        controller.addMember(portfolioId, new AddPortfolioMemberRequest(targetId), analyst);

        verify(targetRepository).updatePortfolio(targetId, portfolioId);
        verify(auditLogRepository)
                .record(eq(orgId), any(), any(), eq("PORTFOLIO_MEMBER_ADDED"), eq("PORTFOLIO"), any(), any());
    }

    @Test
    void removeMember_targetNotActuallyAMember_notFound() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio()));
        when(targetRepository.isInPortfolio(targetId, portfolioId)).thenReturn(false);

        assertThatThrownBy(() -> controller.removeMember(portfolioId, targetId, analyst))
                .isInstanceOf(ResponseStatusException.class);
        verify(targetRepository, never()).updatePortfolio(any(), any());
    }

    @Test
    void removeMember_actualMember_clearsPortfolioId() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio()));
        when(targetRepository.isInPortfolio(targetId, portfolioId)).thenReturn(true);
        when(portfolioService.computeDetail(any())).thenReturn(emptyDetail());

        controller.removeMember(portfolioId, targetId, analyst);

        verify(targetRepository).updatePortfolio(targetId, null);
    }

    @Test
    void delete_ownedPortfolio_deletesAndAudits_neverTouchesTargets() {
        when(portfolioRepository.findByIdAndOrganization(portfolioId, orgId)).thenReturn(Optional.of(portfolio()));

        controller.delete(portfolioId, analyst);

        verify(portfolioRepository).delete(portfolioId);
        verify(targetRepository, never()).updatePortfolio(any(), any());
        verify(targetRepository, never()).delete(any());
        verify(auditLogRepository)
                .record(eq(orgId), any(), any(), eq("PORTFOLIO_DELETED"), eq("PORTFOLIO"), any(), any());
    }

    @Test
    void delete_viewerRole_forbidden() {
        assertThatThrownBy(() -> controller.delete(portfolioId, viewer)).isInstanceOf(ResponseStatusException.class);
    }
}
