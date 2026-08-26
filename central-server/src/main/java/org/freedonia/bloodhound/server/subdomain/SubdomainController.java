package org.freedonia.bloodhound.server.subdomain;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class SubdomainController {

    private final SubdomainRepository subdomainRepository;
    private final TargetRepository targetRepository;

    public SubdomainController(SubdomainRepository subdomainRepository, TargetRepository targetRepository) {
        this.subdomainRepository = subdomainRepository;
        this.targetRepository = targetRepository;
    }

    @GetMapping("/api/v1/targets/{id}/subdomains")
    public List<SubdomainSummary> list(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return subdomainRepository.findByTarget(id).stream().map(SubdomainSummary::from).toList();
    }
}
