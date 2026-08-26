package org.freedonia.bloodhound.server.scim.dto;

import jakarta.validation.constraints.NotBlank;

public record CreateScimTokenRequest(@NotBlank String label) {}
