package org.freedonia.bloodhound.server.apikey.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * {@code expiresInDays} is optional - null falls back to {@code ApiKeyController.DEFAULT_EXPIRY_DAYS}.
 *
 * <p>{@code @Size(max=200)} on label - a security review found this was the one free-text field
 * left uncapped, unlike every other admin-authored label/name capped this session (SCIM
 * userName/displayName, MCP client_name, target notes/attestationText) - this renders back
 * verbatim on ApiKeysPage's own list, the same "unbounded value stored + rendered in the UI" gap.
 */
public record CreateApiKeyRequest(
        @NotBlank @Size(max = 200) String label, @Min(1) @Max(365) Integer expiresInDays) {}
