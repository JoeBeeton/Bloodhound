package org.freedonia.bloodhound.server.target.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record CreateTargetRequest(
        @NotBlank
                @Pattern(
                        regexp = "^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$",
                        message = "must be a valid domain name")
                String hostname,
        @NotBlank @Pattern(regexp = "OWN|COMPETITOR|WATCHLIST") String targetType) {}
