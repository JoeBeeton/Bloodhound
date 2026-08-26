package org.freedonia.bloodhound.server.auth.sso.dto;

import jakarta.validation.constraints.NotBlank;

public record IdentityProviderConfigRequest(
        @NotBlank String idpEntityId,
        @NotBlank String idpSsoUrl,
        @NotBlank String idpX509Cert,
        @NotBlank String emailAttributeName,
        String displayNameAttributeName,
        boolean enabled) {}
