package org.freedonia.bloodhound.server.orgs.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank String currentPassword, @NotBlank @Size(min = 8, max = 200) String newPassword) {}
