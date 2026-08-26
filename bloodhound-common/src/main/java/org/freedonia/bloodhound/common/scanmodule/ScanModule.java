package org.freedonia.bloodhound.common.scanmodule;

/**
 * SPI implemented by every Tier 1 (and later Tier 2) scan module. Worker
 * resolves a job's {@code module_type} string to a bean implementing this
 * interface, so adding a module is: implement + register, no dispatch-loop
 * changes required.
 */
public interface ScanModule {

    /**
     * Unique key matching {@code scan_jobs.module_type}, e.g. "DNS_POSTURE".
     */
    String moduleType();

    ScanTier tier();

    ModuleResult execute(ScanContext context) throws ScanModuleException;
}
