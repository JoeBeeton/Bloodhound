package org.freedonia.bloodhound.server.orgs.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record CreateUserRequest(
        @NotBlank @Email String email,
        @NotBlank String displayName,
        @NotBlank @Pattern(regexp = "ADMIN|ANALYST|VIEWER") String role) {}
