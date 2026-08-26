package org.freedonia.bloodhound.worker.modules.common;

import java.util.ArrayList;
import java.util.List;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;

/**
 * Reads the capped subdomain list ScanRunService hands over in a job's
 * payload (the worker has no database access of its own, so it can't learn a
 * target's already-discovered subdomains any other way - see
 * ScanContext#jobPayload()). Originally private to FingerprintModule;
 * extracted here once multiple modules needed the identical parsing.
 */
public final class PayloadSubdomains {

    private PayloadSubdomains() {}

    public static List<String> from(ScanContext context) {
        Object raw = context.jobPayload() == null ? null : context.jobPayload().get("subdomains");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<String> hostnames = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                hostnames.add(String.valueOf(item));
            }
        }
        return hostnames;
    }

    /**
     * The single-host counterpart to {@link #from} - Tier 2 jobs (see
     * ScanRunService#createDeepScan) carry {@code {"host": "..."}}, one job
     * per host, rather than a shared multi-host list. Falls back to
     * {@code context.hostname()} (the target's root) if the payload has no
     * "host" key, which only happens for a job predating this per-host
     * dispatch scheme - a defensive fallback, not the normal path.
     */
    public static String singleHost(ScanContext context) {
        Object raw = context.jobPayload() == null ? null : context.jobPayload().get("host");
        return raw != null ? String.valueOf(raw) : context.hostname();
    }
}
