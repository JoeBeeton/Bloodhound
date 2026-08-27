package org.freedonia.bloodhound.server.apikey.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/** {@code expiresInDays} is optional - null falls back to {@code ApiKeyController.DEFAULT_EXPIRY_DAYS}. */
public record CreateApiKeyRequest(
        @NotBlank String label, @Min(1) @Max(365) Integer expiresInDays) {}
