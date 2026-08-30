package org.freedonia.bloodhound.server.scim;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.scim.dto.CreateScimTokenRequest;
import org.freedonia.bloodhound.server.scim.dto.CreateScimTokenResponse;
import org.freedonia.bloodhound.server.scim.dto.ScimTokenSummary;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
 * Admin-facing SCIM bearer token management, under normal JWT auth - distinct
 * from the SCIM protocol endpoints themselves (scim/v2/**, ROLE_SCIM), which
 * an IdP calls using the tokens minted here.
 */
@RestController
@RequestMapping("/api/v1/orgs/{orgId}/scim-tokens")
@PreAuthorize("hasRole('ADMIN')")
public class ScimTokenAdminController {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final ScimTokenRepository scimTokenRepository;
    private final String spBaseUrl;

    public ScimTokenAdminController(
            ScimTokenRepository scimTokenRepository, @Value("${bloodhound.saml.sp-base-url}") String spBaseUrl) {
        this.scimTokenRepository = scimTokenRepository;
        this.spBaseUrl = spBaseUrl;
    }

    public record ScimTokensResponse(String scimBaseUrl, List<ScimTokenSummary> tokens) {}

    @GetMapping
    public ScimTokensResponse list(@PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        List<ScimTokenSummary> tokens = scimTokenRepository.findByOrganization(orgId).stream()
                .map(ScimTokenSummary::from)
                .toList();
        return new ScimTokensResponse(spBaseUrl + "/scim/v2", tokens);
    }

    @PostMapping
    public ResponseEntity<CreateScimTokenResponse> create(
            @PathVariable UUID orgId, @AuthenticationPrincipal JwtPrincipal principal, @Valid @RequestBody CreateScimTokenRequest request) {
        requireSameOrg(orgId, principal);
        // Unlike API keys, no forced default here - null (never expires) is a deliberate,
        // supported choice for a continuous directory-sync credential, not a gap to close later.
        // See V44__scim_token_expiry.sql for the full reasoning.
        Instant expiresAt =
                request.expiresInDays() != null ? Instant.now().plus(request.expiresInDays(), ChronoUnit.DAYS) : null;
        byte[] raw = new byte[32];
        SECURE_RANDOM.nextBytes(raw);
        String token = "scim_" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        ScimToken created = scimTokenRepository.insert(orgId, request.label(), HashUtil.sha256Hex(token), expiresAt);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new CreateScimTokenResponse(created.id(), created.label(), token, created.createdAt(), created.expiresAt()));
    }

    @DeleteMapping("/{tokenId}")
    public ResponseEntity<Void> revoke(
            @PathVariable UUID orgId, @PathVariable UUID tokenId, @AuthenticationPrincipal JwtPrincipal principal) {
        requireSameOrg(orgId, principal);
        int updated = scimTokenRepository.revoke(tokenId, orgId);
        if (updated == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "SCIM token not found");
        }
        return ResponseEntity.noContent().build();
    }

    private void requireSameOrg(UUID orgId, JwtPrincipal principal) {
        if (!orgId.equals(principal.organizationId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
