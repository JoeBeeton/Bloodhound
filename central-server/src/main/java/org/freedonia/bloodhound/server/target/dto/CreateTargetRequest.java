package org.freedonia.bloodhound.server.target.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.freedonia.bloodhound.server.target.HostnamePattern;

public record CreateTargetRequest(
        @NotBlank
                @Pattern(regexp = HostnamePattern.REGEX, message = "must be a valid domain name")
                String hostname,
        @NotBlank @Pattern(regexp = "OWN|COMPETITOR|WATCHLIST") String targetType) {}
