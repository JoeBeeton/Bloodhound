package org.freedonia.bloodhound.server.apikey;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.apikey.dto.ApiKeySummary;
import org.freedonia.bloodhound.server.apikey.dto.CreateApiKeyRequest;
import org.freedonia.bloodhound.server.apikey.dto.CreateApiKeyResponse;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.security.HashUtil;
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
 * Self-service management of the caller's own read-only external API keys -
 * requires an already-authenticated JWT session (i.e. you have to log in to
 * generate one), same as every other route in the main security chain. The
 * keys minted here authenticate against the separate data-retrieval API
 * documented at /swagger-ui.html via {@link ApiKeyAuthFilter}, not against
 * this controller's own routes - a leaked key cannot be used to list, create,
 * or revoke other keys, only to read ASM data.
 *
 * <p>A user sees and revokes only their own keys, except an ADMIN, who may
 * additionally revoke any key within their organization (offboarding a
 * departed teammate's key without needing their credentials).
 */
@RestController
@RequestMapping("/api/v1/api-keys")
@Tag(name = "API Keys", description = "Manage your own read-only external API keys (JWT session required - not usable with an API key itself)")
// Overrides OpenApiConfig's global ApiKeyAuth requirement with JwtSessionAuth - a live API
// review found the generated spec showing the generic API-key bearer scheme here, directly
// contradicting this controller's own @Tag description above and SecurityConfig's real
// enforcement (ROLE_API_KEY is deliberately excluded from every route in this controller).
@SecurityRequirement(name = org.freedonia.bloodhound.server.config.OpenApiConfig.JWT_SESSION_SCHEME)
public class ApiKeyController {

    /** No forever-lived keys by default - a deliberately bounded credential handed to external tooling. */
    static final int DEFAULT_EXPIRY_DAYS = 90;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int PREFIX_DISPLAY_LENGTH = 12;

    private final ApiKeyRepository apiKeyRepository;

    public ApiKeyController(ApiKeyRepository apiKeyRepository) {
        this.apiKeyRepository = apiKeyRepository;
    }

    @Operation(summary = "List your own API keys (never returns the raw key or its hash)")
    @GetMapping
    public List<ApiKeySummary> list(@AuthenticationPrincipal JwtPrincipal principal) {
        Instant now = Instant.now();
        return apiKeyRepository.findByCreatedByUser(principal.userId()).stream()
                .map(key -> ApiKeySummary.from(key, now))
                .toList();
    }

    @Operation(summary = "Generate a new API key - the raw key is returned exactly once, in this response only")
    @PostMapping
    public ResponseEntity<CreateApiKeyResponse> create(
            @AuthenticationPrincipal JwtPrincipal principal, @Valid @RequestBody CreateApiKeyRequest request) {
        int expiryDays = request.expiresInDays() != null ? request.expiresInDays() : DEFAULT_EXPIRY_DAYS;
        Instant expiresAt = Instant.now().plus(expiryDays, ChronoUnit.DAYS);

        byte[] raw = new byte[32];
        SECURE_RANDOM.nextBytes(raw);
        String token = "bhk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String keyPrefix = token.substring(0, Math.min(PREFIX_DISPLAY_LENGTH, token.length()));

        ApiKey created = apiKeyRepository.insert(
                principal.organizationId(), principal.userId(), request.label(), keyPrefix, HashUtil.sha256Hex(token), expiresAt);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new CreateApiKeyResponse(
                        created.id(), created.label(), created.keyPrefix(), token, created.createdAt(), created.expiresAt()));
    }

    @Operation(summary = "Revoke an API key immediately (your own key, or any key in your org if you're an admin)")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revoke(@PathVariable UUID id, @AuthenticationPrincipal JwtPrincipal principal) {
        int updated = apiKeyRepository.revokeOwnedByUser(id, principal.userId());
        if (updated == 0 && "ADMIN".equals(principal.role())) {
            updated = apiKeyRepository.revokeWithinOrganization(id, principal.organizationId());
        }
        if (updated == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.noContent().build();
    }
}
