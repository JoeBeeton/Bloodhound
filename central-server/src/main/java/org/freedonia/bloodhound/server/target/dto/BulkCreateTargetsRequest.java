package org.freedonia.bloodhound.server.target.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Deliberately does NOT validate each hostname's format here the way CreateTargetRequest's own
 * @Pattern does - a single malformed line in an otherwise-good batch would fail the whole request
 * under bean validation (it rejects the request as a unit, not per-element), defeating the entire
 * point of a bulk endpoint. TargetController#createBulk validates each hostname imperatively
 * instead, so one bad line becomes one rejected result alongside the rest of the batch's
 * successes, not a 400 for everything.
 *
 * <p>100 is a batch-size ceiling, not the org-wide cap (see TargetController's own
 * maxTargetsPerOrg) - defensive against a pathologically large paste, not a real limit on how big
 * a legitimate domain-portfolio onboarding would be.
 */
public record BulkCreateTargetsRequest(
        @NotEmpty @Size(max = 100) List<@NotBlank String> hostnames,
        @NotBlank @Pattern(regexp = "OWN|COMPETITOR|WATCHLIST") String targetType) {}
