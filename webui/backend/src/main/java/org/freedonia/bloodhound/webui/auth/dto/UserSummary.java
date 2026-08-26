package org.freedonia.bloodhound.webui.auth.dto;

import java.util.UUID;

public record UserSummary(UUID id, String email, String displayName, String role, UUID organizationId) {}
