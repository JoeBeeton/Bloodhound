package org.freedonia.bloodhound.common.scanmodule;

/**
 * TIER_1 modules are passive/OSINT-safe and run against any tracked target,
 * including competitor/watchlist domains without prior authorization.
 * TIER_2 modules are active (deep port scan, ZAP) and must only ever be scheduled
 * against targets with an AUTHORIZED attestation. Phase 1 implements TIER_1
 * modules only; this enum exists now so the seam is real from the start.
 */
public enum ScanTier {
    TIER_1,
    TIER_2
}
