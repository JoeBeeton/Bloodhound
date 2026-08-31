package org.freedonia.bloodhound.server.target.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
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
 *
 * <p>scanCadenceSeconds had no bounds at all until the same review found it too - unlike a bad
 * notes value (just clutter), a bad cadence here is a real abuse vector: ScanAutoScheduler#sweep
 * computes {@code next_scan_at = now() + Duration.ofSeconds(cadence)}, so a zero or negative
 * value keeps next_scan_at in the past forever, and its own 5-minute poll would re-trigger a real
 * scan against that (possibly third-party, per CreateTargetRequest's own SSRF-relevant hostname
 * check) domain on every single sweep, indefinitely - sustained unwanted outbound scanning
 * traffic, the same reputational/abuse category that hostname check already guards against, just
 * reached through a different field. The frontend only ever sends one of 5 fixed values via a
 * &lt;select&gt; (6h-7d, see schedule.ts's own SCHEDULE_OPTIONS) - 1h-30d gives generous headroom
 * around that real range without reopening the abuse case a sub-hour or huge value would allow.
 *
 * <p>targetType reuses CreateTargetRequest's own OWN|COMPETITOR|WATCHLIST pattern - see
 * TargetRepository#updateTargetType for why a mis-picked type at creation previously had no fix
 * short of a destructive delete-and-recreate.
 */
public record UpdateTargetRequest(
        @Min(3600) @Max(2592000) Integer scanCadenceSeconds,
        Boolean isActive,
        @Size(max = 2000) String notes,
        @Pattern(regexp = "OWN|COMPETITOR|WATCHLIST") String targetType) {}
