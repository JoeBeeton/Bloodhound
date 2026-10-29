package org.freedonia.bloodhound.server.integrations.github;

import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.security.SecretCredentialCipher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Admin-facing CRUD for the GITHUB_SECRET_SEARCH integration - same org-scoping/role-gating
 * shape as {@code SlackIntegrationController}. Unlike Slack's plaintext-at-rest webhook URL,
 * the token here is encrypted ({@link SecretCredentialCipher}) and this controller never
 * decrypts it for any reason - not even to build a masked preview, which Slack's masking does
 * (Slack's secret is plaintext in the DB already, so masking it costs nothing extra; doing the
 * same here would mean decrypting on every admin page load just to redact most of the result,
 * a real cost for no real benefit). Responses report only whether a token is configured and
 * enabled, never any part of its value. The ONLY place this token is ever decrypted is {@link
 * org.freedonia.bloodhound.server.jobqueue.JobController}'s worker-facing internal endpoint,
 * which needs the real value to call GitHub's API.
 */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/github-secret-search-integration")
@PreAuthorize("hasRole('ADMIN')")
public class GithubSecretSearchIntegrationController {

    /** A token shorter than this can't be a real GitHub PAT of any known format - not a strict format check (GitHub has several valid prefixes and could add more), just a sanity floor. */
    private static final int MIN_TOKEN_LENGTH = 20;

    private final GithubSecretSearchIntegrationRepository repository;
    private final SecretCredentialCipher cipher;
    private final AuditLogRepository auditLogRepository;

    public GithubSecretSearchIntegrationController(
            GithubSecretSearchIntegrationRepository repository,
            SecretCredentialCipher cipher,
            AuditLogRepository auditLogRepository) {
        this.repository = repository;
        this.cipher = cipher;
        this.auditLogRepository = auditLogRepository;
    }

    public record IntegrationRequest(
            /** Null/blank means "keep the currently-stored token unchanged" - see #save. Required on first save. */
            String token,
            boolean enabled) {}

    /** Never carries any part of the real token - see this class's own javadoc on why there's no masked preview at all. */
    public record IntegrationResponse(
            UUID id, UUID organizationId, boolean enabled, java.time.Instant updatedAt) {}

    /** Same reasoning as {@code SlackIntegrationController.ErrorMessageResponse} - the app's default error handler never exposes a ResponseStatusException's reason text to the caller. */
    public record ErrorMessageResponse(String message) {}

    @GetMapping
    public ResponseEntity<?> get(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        return repository
                .findByOrganization(orgId)
                .map(i -> ResponseEntity.ok(toResponse(i)))
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    @PutMapping
    public ResponseEntity<?> save(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal JwtPrincipal principal,
            @RequestBody IntegrationRequest request) {
        requireSameOrg(orgId, principal);
        if (!cipher.isConfigured()) {
            // Same "feature visibly unavailable, not silently insecure" stance as the encryption
            // key's own doc comment - never falls back to storing a token any other way.
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new ErrorMessageResponse(
                            "Secret encryption is not configured on this server - contact your administrator."));
        }
        String token = request.token();
        if (token == null || token.isBlank()) {
            // The frontend never has the real token to re-submit (there's no masked preview to
            // even partially echo back - see this class's own javadoc) - a blank field here
            // means "only changing enabled," not "clear the token." Requires an existing row;
            // there's nothing to keep on a first-ever save. Toggles enabled without decrypting
            // or re-encrypting the unchanged token at all - see
            // GithubSecretSearchIntegrationRepository#updateEnabledOnly.
            if (repository.findByOrganization(orgId).isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessageResponse("token is required"));
            }
            repository.updateEnabledOnly(orgId, request.enabled());
            GithubSecretSearchIntegration saved = repository.findByOrganization(orgId).orElseThrow();
            return ok(orgId, principal, saved);
        }
        if (token.length() < MIN_TOKEN_LENGTH) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorMessageResponse("token is too short to be a real GitHub personal access token"));
        }
        GithubSecretSearchIntegration saved = repository.upsert(orgId, token, request.enabled());
        return ok(orgId, principal, saved);
    }

    private ResponseEntity<?> ok(UUID orgId, JwtPrincipal principal, GithubSecretSearchIntegration saved) {
        // Never logs the token itself, only that one was set and the resulting enabled state -
        // same restraint SlackIntegrationController's own audit entries already apply.
        auditLogRepository.record(
                orgId,
                principal.userId(),
                principal.email(),
                "GITHUB_SECRET_SEARCH_INTEGRATION_SAVED",
                "ORGANIZATION",
                orgId.toString(),
                "enabled=" + saved.enabled());
        return ResponseEntity.ok(toResponse(saved));
    }

    @DeleteMapping
    public ResponseEntity<Void> delete(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        repository.delete(orgId);
        auditLogRepository.record(
                orgId,
                principal.userId(),
                principal.email(),
                "GITHUB_SECRET_SEARCH_INTEGRATION_REMOVED",
                "ORGANIZATION",
                orgId.toString(),
                null);
        return ResponseEntity.noContent().build();
    }

    private IntegrationResponse toResponse(GithubSecretSearchIntegration i) {
        return new IntegrationResponse(i.id(), i.organizationId(), i.enabled(), i.updatedAt());
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
