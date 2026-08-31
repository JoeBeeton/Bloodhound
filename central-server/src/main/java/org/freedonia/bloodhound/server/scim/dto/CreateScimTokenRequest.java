package org.freedonia.bloodhound.server.scim.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * expiresInDays is optional and, unlike API keys, defaults to null (never expires) rather than a
 * forced value - see V44__scim_token_expiry.sql for why a continuous directory-sync credential
 * gets a different default than an ad-hoc API key.
 *
 * <p>{@code @Size(max=200)} on label - same gap, same fix as the sibling CreateApiKeyRequest:
 * this had no length cap at all despite rendering back verbatim on AdminScimPage's own list.
 */
public record CreateScimTokenRequest(
        @NotBlank @Size(max = 200) String label, @Min(1) @Max(3650) Integer expiresInDays) {}
