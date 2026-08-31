package org.freedonia.bloodhound.server.orgs.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * A security review found this had no length cap on email/displayName at all - the same
 * "attacker/misconfiguration-influenced free text stored unbounded" gap already fixed for SCIM
 * user provisioning (ScimUsersController) and the MCP OAuth2 client_name field this session. Both
 * write into the same shared {@code users} table's email/display_name columns (plain TEXT, no
 * DB-level limit either) that the SCIM fix already capped for the SCIM-provisioned path - an admin
 * account created here is lower-risk (requires an authenticated ADMIN, not a bare bearer token),
 * but the caps are cheap and keep every path into this shared table consistent. Same specific
 * values the SCIM fix uses: 320 (RFC 5321's own max total email length) and 200 (matching the MCP
 * client_name precedent).
 */
public record CreateUserRequest(
        @NotBlank @Email @Size(max = 320) String email,
        @NotBlank @Size(max = 200) String displayName,
        @NotBlank @Pattern(regexp = "ADMIN|ANALYST|VIEWER") String role) {}
