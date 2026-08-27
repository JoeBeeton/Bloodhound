package org.freedonia.bloodhound.server.typosquat;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.freedonia.bloodhound.server.typosquat.dto.TyposquatCandidateSummary;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class TyposquatController {

    private final TyposquatCandidateRepository repository;
    private final TargetRepository targetRepository;

    public TyposquatController(TyposquatCandidateRepository repository, TargetRepository targetRepository) {
        this.repository = repository;
        this.targetRepository = targetRepository;
    }

    @GetMapping("/api/v1/targets/{id}/typosquats")
    public List<TyposquatCandidateSummary> list(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return repository.findRegisteredByTarget(id).stream().map(TyposquatCandidateSummary::from).toList();
    }

    /**
     * Raw PNG bytes, not wrapped in JSON - lets the frontend point an {@code <img src>}
     * directly at this endpoint (with the auth header attached the same way apiFetch already
     * attaches it for every other request) rather than base64-inflating the image into the
     * list response above, which every caller of {@link #list} would pay for whether or not
     * they ever render a thumbnail.
     */
    @GetMapping("/api/v1/targets/{id}/typosquats/{candidateId}/screenshot")
    public ResponseEntity<byte[]> screenshot(
            @PathVariable UUID id, @PathVariable UUID candidateId, @AuthenticationPrincipal JwtPrincipal principal) {
        targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        byte[] png = repository
                .findScreenshotPng(id, candidateId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(png);
    }
}
