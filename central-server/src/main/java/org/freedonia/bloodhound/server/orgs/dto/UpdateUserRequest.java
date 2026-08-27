package org.freedonia.bloodhound.server.orgs.dto;

import jakarta.validation.constraints.Pattern;

/**
 * Partial update - null fields are left unchanged. {@code @Pattern} (not {@code @NotBlank})
 * deliberately allows null through unvalidated - Bean Validation only applies a constraint when
 * the value is present - while still rejecting any non-null value outside the allow-list. Added
 * after a security review noted this was the one write DTO in the codebase without one (unlike
 * {@link CreateUserRequest}'s role field): no actual privilege-escalation path existed even
 * without it (a bogus role/status string matches no granted authority, and the DB's own
 * users_role_check/users_status_check constraints would reject it anyway), but a malformed value
 * now fails cleanly as a 400 here instead of surfacing as an unhandled DB constraint violation.
 */
public record UpdateUserRequest(
        @Pattern(regexp = "ADMIN|ANALYST|VIEWER") String role,
        @Pattern(regexp = "ACTIVE|DISABLED|PENDING_PROVISION") String status) {}
