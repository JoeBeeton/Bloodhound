package org.freedonia.bloodhound.server.target;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
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
 * The attestation flow that flips targets.authorization_status - the gate
 * Tier 2 active scanning (deep port scan, and OWASP ZAP once it lands) checks
 * before it will ever touch a target. This is a deliberate, logged action:
 * every authorize call requires real attestation text and is attributed to
 * the calling user, never a bare toggle.
 */
@RestController
@RequestMapping("/api/v1/targets/{id}/authorization")
public class TargetAuthorizationController {

    private final TargetRepository targetRepository;
    private final TargetAuthorizationRepository authorizationRepository;

    public TargetAuthorizationController(
            TargetRepository targetRepository, TargetAuthorizationRepository authorizationRepository) {
        this.targetRepository = targetRepository;
        this.authorizationRepository = authorizationRepository;
    }

    @GetMapping
    public AuthorizationStatusResponse get(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = requireOwnedTarget(id, principal);
        List<TargetAuthorization> history = authorizationRepository.findHistory(id);
        return AuthorizationStatusResponse.of(target.authorizationStatus(), history);
    }

    @PostMapping
    public ResponseEntity<AuthorizationStatusResponse> authorize(
            @PathVariable UUID id,
            @jakarta.validation.Valid @RequestBody AuthorizeRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        requireOwnedTarget(id, principal);
        authorizationRepository.authorize(id, principal.userId(), request.attestationText());
        Target updated = targetRepository.findById(id).orElseThrow();
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(AuthorizationStatusResponse.of(updated.authorizationStatus(), authorizationRepository.findHistory(id)));
    }

    @DeleteMapping
    public AuthorizationStatusResponse revoke(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        requireWriteAccess(principal);
        requireOwnedTarget(id, principal);
        authorizationRepository.revokeCurrent(id, principal.userId());
        Target updated = targetRepository.findById(id).orElseThrow();
        return AuthorizationStatusResponse.of(updated.authorizationStatus(), authorizationRepository.findHistory(id));
    }

    private Target requireOwnedTarget(UUID id, JwtPrincipal principal) {
        return targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private static void requireWriteAccess(JwtPrincipal principal) {
        if (!"ADMIN".equals(principal.role()) && !"ANALYST".equals(principal.role())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ADMIN or ANALYST role required");
        }
    }

    public record AuthorizeRequest(@NotBlank String attestationText) {}

    public record AuthorizationEntry(
            UUID id, UUID authorizedByUserId, Instant authorizedAt, String attestationText, Instant revokedAt) {
        static AuthorizationEntry from(TargetAuthorization a) {
            return new AuthorizationEntry(a.id(), a.authorizedByUserId(), a.authorizedAt(), a.attestationText(), a.revokedAt());
        }
    }

    public record AuthorizationStatusResponse(String authorizationStatus, List<AuthorizationEntry> history) {
        static AuthorizationStatusResponse of(String status, List<TargetAuthorization> rawHistory) {
            return new AuthorizationStatusResponse(
                    status, rawHistory.stream().map(AuthorizationEntry::from).toList());
        }
    }
}
