package org.freedonia.bloodhound.server.fingerprint;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.fingerprint.dto.FingerprintSummary;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class FingerprintController {

    private final FingerprintRepository fingerprintRepository;
    private final TargetRepository targetRepository;

    public FingerprintController(FingerprintRepository fingerprintRepository, TargetRepository targetRepository) {
        this.fingerprintRepository = fingerprintRepository;
        this.targetRepository = targetRepository;
    }

    @GetMapping("/api/v1/targets/{id}/fingerprints")
    public List<FingerprintSummary> list(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return fingerprintRepository.findByTarget(id).stream().map(FingerprintSummary::from).toList();
    }
}
