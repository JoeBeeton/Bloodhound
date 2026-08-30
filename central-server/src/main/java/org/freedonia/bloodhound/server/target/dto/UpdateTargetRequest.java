package org.freedonia.bloodhound.server.target.dto;

import jakarta.validation.constraints.Size;

/**
 * Partial update - null fields are left unchanged. notes is the one exception: a blank string is
 * a deliberate clear, not a no-op - see TargetRepository#updateNotes.
 *
 * <p>notes had no length limit at all until an input-validation review found it - unlike every
 * other free-text field a user controls in this app (ChangePasswordRequest's newPassword capped
 * at 200) - could be PATCHed with an arbitrarily large string by any ADMIN/ANALYST, with no
 * client-side feedback either. 2000 characters is generous for its actual purpose (a few
 * sentences of "which environment, who owns it, why it's tracked"), not a real limit on anything
 * a legitimate note would need.
 */
public record UpdateTargetRequest(Integer scanCadenceSeconds, Boolean isActive, @Size(max = 2000) String notes) {}
