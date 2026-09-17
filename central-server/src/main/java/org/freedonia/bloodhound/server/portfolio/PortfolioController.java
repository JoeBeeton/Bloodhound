package org.freedonia.bloodhound.server.portfolio;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.portfolio.dto.AddPortfolioMemberRequest;
import org.freedonia.bloodhound.server.portfolio.dto.CreatePortfolioRequest;
import org.freedonia.bloodhound.server.portfolio.dto.PortfolioDetailResponse;
import org.freedonia.bloodhound.server.portfolio.dto.PortfolioSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Groups several targets (e.g. jaja.co.uk + jaja.finance) into one blended-score view - see
 * PortfolioService for the blend itself. Every write here only ever touches the portfolios table
 * and targets.portfolio_id; a member target's own scans/findings/subdomains are never read from
 * or written to by anything in this controller.
 */
@RestController
@RequestMapping("/api/v1/portfolios")
public class PortfolioController {

    private final PortfolioRepository portfolioRepository;
    private final TargetRepository targetRepository;
    private final PortfolioService portfolioService;
    private final AuditLogRepository auditLogRepository;

    public PortfolioController(
            PortfolioRepository portfolioRepository,
            TargetRepository targetRepository,
            PortfolioService portfolioService,
            AuditLogRepository auditLogRepository) {
        this.portfolioRepository = portfolioRepository;
        this.targetRepository = targetRepository;
        this.portfolioService = portfolioService;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping
    public List<PortfolioSummary> list(@AuthenticationPrincipal JwtPrincipal principal) {
        return portfolioRepository.findByOrganization(principal.organizationId()).stream()
                .map(p -> PortfolioSummary.from(portfolioService.computeDetail(p)))
                .toList();
    }

    @PostMapping
    public ResponseEntity<PortfolioSummary> create(
            @Valid @RequestBody CreatePortfolioRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Portfolio portfolio = portfolioRepository.insert(principal.organizationId(), request.name());
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "PORTFOLIO_CREATED",
                "PORTFOLIO",
                portfolio.id().toString(),
                "name=" + portfolio.name());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(PortfolioSummary.from(portfolioService.computeDetail(portfolio)));
    }

    @GetMapping("/{id}")
    public PortfolioDetailResponse get(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        Portfolio portfolio = requireOwnedPortfolio(id, principal);
        return PortfolioDetailResponse.from(portfolioService.computeDetail(portfolio));
    }

    /** Adding a target already in another portfolio simply moves it - see TargetRepository#updatePortfolio. */
    @PostMapping("/{id}/members")
    public ResponseEntity<PortfolioDetailResponse> addMember(
            @PathVariable UUID id,
            @Valid @RequestBody AddPortfolioMemberRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Portfolio portfolio = requireOwnedPortfolio(id, principal);
        Target target = targetRepository
                .findByIdAndOrganization(request.targetId(), principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        targetRepository.updatePortfolio(target.id(), portfolio.id());
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "PORTFOLIO_MEMBER_ADDED",
                "PORTFOLIO",
                portfolio.id().toString(),
                "targetHostname=" + target.hostname());
        return ResponseEntity.ok(PortfolioDetailResponse.from(portfolioService.computeDetail(portfolio)));
    }

    @DeleteMapping("/{id}/members/{targetId}")
    public ResponseEntity<PortfolioDetailResponse> removeMember(
            @PathVariable UUID id, @PathVariable UUID targetId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Portfolio portfolio = requireOwnedPortfolio(id, principal);
        if (!targetRepository.isInPortfolio(targetId, id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        targetRepository.updatePortfolio(targetId, null);
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "PORTFOLIO_MEMBER_REMOVED",
                "PORTFOLIO",
                portfolio.id().toString(),
                "targetId=" + targetId);
        return ResponseEntity.ok(PortfolioDetailResponse.from(portfolioService.computeDetail(portfolio)));
    }

    /** Never touches member targets - only the grouping (portfolios row + the FK, cleared via ON DELETE SET NULL) is removed. Not ADMIN-only like Target#delete's hard delete, since nothing irreversible happens to any target's own data here. */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        Portfolio portfolio = requireOwnedPortfolio(id, principal);
        portfolioRepository.delete(id);
        auditLogRepository.record(
                principal.organizationId(),
                principal.userId(),
                principal.email(),
                "PORTFOLIO_DELETED",
                "PORTFOLIO",
                portfolio.id().toString(),
                "name=" + portfolio.name());
        return ResponseEntity.noContent().build();
    }

    private Portfolio requireOwnedPortfolio(UUID id, JwtPrincipal principal) {
        return portfolioRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private static void requireWriteAccess(JwtPrincipal principal) {
        if (!"ADMIN".equals(principal.role()) && !"ANALYST".equals(principal.role())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ADMIN or ANALYST role required");
        }
    }
}
