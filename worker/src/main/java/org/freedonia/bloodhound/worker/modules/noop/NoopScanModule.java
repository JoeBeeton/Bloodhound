package org.freedonia.bloodhound.worker.modules.noop;

import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.springframework.stereotype.Component;

/**
 * Milestone 2's only module: proves the full claim -> dispatch -> execute ->
 * report round trip end to end before any real Tier 1 module exists. Sleeps
 * briefly so the CLAIMED -> RUNNING -> COMPLETE transition is actually
 * observable rather than instantaneous.
 */
@Component
public class NoopScanModule implements ScanModule {

    @Override
    public String moduleType() {
        return "NOOP";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        try {
            Thread.sleep(1500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanModuleException("interrupted", e);
        }
        return new ModuleResult(List.of(), Map.of("note", "noop module - no real scanning performed"));
    }
}
