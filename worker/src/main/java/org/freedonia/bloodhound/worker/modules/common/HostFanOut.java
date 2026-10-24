package org.freedonia.bloodhound.worker.modules.common;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runs a per-host check against a target's root hostname plus its known
 * subdomains, with bounded concurrency and a per-host timeout - the shared
 * pattern originally built for TECH_FINGERPRINT and now reused by every Tier
 * 1 module that needs to see the full discovered surface, not just the bare
 * apex (HTTP_HEADERS, TLS_ANALYSIS, PORT_SCAN_LIGHT, TECH_FINGERPRINT). This
 * exists because a target's apex can legitimately have no A/AAAA record at
 * all while its real web presence lives entirely on subdomains - scanning
 * only the apex in that case finds nothing, which is exactly the gap this
 * class closes.
 *
 * <p>Failure semantics are deliberately host-count-based, not root-biased:
 * one or a few unreachable hosts among many (the apex included) is normal
 * and expected - that host is skipped and scanning continues with whatever
 * else responds. Only when <em>every</em> attempted host fails does this
 * throw, since at that point nothing was actually scanned.
 */
public final class HostFanOut {

    private static final Logger log = LoggerFactory.getLogger(HostFanOut.class);

    private HostFanOut() {}

    @FunctionalInterface
    public interface HostTask {
        List<RawFinding> run(String hostname) throws Exception;
    }

    public record Result(List<RawFinding> findings, List<String> hostsCovered, int hostsAttempted) {}

    /**
     * @param subdomains known subdomains for this target (already capped by the caller's payload builder, but limited again here defensively)
     * @param cap maximum number of subdomains attempted in addition to the root hostname
     * @param poolSize how many hosts are probed concurrently
     * @param perHostTimeoutSeconds hard ceiling per host; a task that hangs past this is abandoned (counted as a failure for that host only)
     */
    public static Result run(
            String rootHostname,
            List<String> subdomains,
            int cap,
            int poolSize,
            long perHostTimeoutSeconds,
            HostTask task)
            throws ScanModuleException {
        Set<String> hosts = new LinkedHashSet<>();
        hosts.add(rootHostname);
        subdomains.stream().limit(cap).forEach(hosts::add);
        List<String> orderedHosts = new ArrayList<>(hosts);

        ExecutorService pool = Executors.newFixedThreadPool(Math.min(poolSize, orderedHosts.size()));
        try {
            List<Future<List<RawFinding>>> futures = new ArrayList<>();
            for (String hostname : orderedHosts) {
                futures.add(pool.submit(() -> {
                    requireSafeHost(hostname);
                    return task.run(hostname);
                }));
            }

            List<RawFinding> allFindings = new ArrayList<>();
            List<String> covered = new ArrayList<>();
            for (int i = 0; i < futures.size(); i++) {
                String hostname = orderedHosts.get(i);
                try {
                    List<RawFinding> findings = futures.get(i).get(perHostTimeoutSeconds, TimeUnit.SECONDS);
                    allFindings.addAll(findings);
                    covered.add(hostname);
                } catch (Exception e) {
                    log.debug("scan of {} skipped: {}", hostname, e.getMessage());
                    // On a per-host timeout the task would otherwise keep
                    // occupying its pool thread for the rest of this
                    // module's run (pool.shutdownNow() only reclaims it once
                    // every host has been processed) - cancel it immediately
                    // instead so a slow host doesn't reduce effective
                    // concurrency for the hosts still queued behind it.
                    futures.get(i).cancel(true);
                }
            }

            if (covered.isEmpty()) {
                int subdomainCount = orderedHosts.size() - 1;
                throw new ScanModuleException(rootHostname + " and all " + subdomainCount
                        + " known subdomain(s) were unreachable - nothing could be scanned");
            }
            return new Result(allFindings, covered, orderedHosts.size());
        } finally {
            pool.shutdownNow();
        }
    }

    @FunctionalInterface
    public interface HostValueTask<T> {
        T run(String hostname) throws Exception;
    }

    public record ValueResult<T>(List<T> perHostResults, List<String> hostsCovered, int hostsAttempted) {}

    /**
     * Same concurrency/timeout/coverage semantics as {@link #run}, but for
     * modules that need one arbitrary result value per host (e.g. a
     * fingerprint record) rather than a flattened list of findings. A host
     * whose task throws or times out is simply omitted from the result -
     * only when every attempted host fails does this throw, exactly as in
     * {@link #run}.
     */
    public static <T> ValueResult<T> runPerHost(
            String rootHostname,
            List<String> subdomains,
            int cap,
            int poolSize,
            long perHostTimeoutSeconds,
            HostValueTask<T> task)
            throws ScanModuleException {
        Set<String> hosts = new LinkedHashSet<>();
        hosts.add(rootHostname);
        subdomains.stream().limit(cap).forEach(hosts::add);
        List<String> orderedHosts = new ArrayList<>(hosts);

        ExecutorService pool = Executors.newFixedThreadPool(Math.min(poolSize, orderedHosts.size()));
        try {
            List<Future<T>> futures = new ArrayList<>();
            for (String hostname : orderedHosts) {
                futures.add(pool.submit(() -> {
                    requireSafeHost(hostname);
                    return task.run(hostname);
                }));
            }

            List<T> results = new ArrayList<>();
            List<String> covered = new ArrayList<>();
            for (int i = 0; i < futures.size(); i++) {
                String hostname = orderedHosts.get(i);
                try {
                    T result = futures.get(i).get(perHostTimeoutSeconds, TimeUnit.SECONDS);
                    results.add(result);
                    covered.add(hostname);
                } catch (Exception e) {
                    log.debug("fingerprinting of {} skipped: {}", hostname, e.getMessage());
                    futures.get(i).cancel(true);
                }
            }

            if (covered.isEmpty()) {
                int subdomainCount = orderedHosts.size() - 1;
                throw new ScanModuleException(rootHostname + " and all " + subdomainCount
                        + " known subdomain(s) were unreachable - nothing could be scanned");
            }
            return new ValueResult<>(results, covered, orderedHosts.size());
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * SSRF guard applied once, here, for every module that fans out via this
     * class (HTTP_HEADERS, TLS_ANALYSIS, PORT_SCAN_LIGHT, TECH_FINGERPRINT) -
     * the root hostname is already checked at target
     * creation (see central-server's TargetController), but subdomains are
     * discovered later from crt.sh/subfinder and never go through that check;
     * a malicious or compromised domain could publish a CT-logged certificate
     * for a subdomain whose DNS record points at 169.254.169.254 or an
     * internal address, and without this, every fanned-out module would
     * happily connect to it. A host that fails this check is treated exactly
     * like any other unreachable host: skipped, not a whole-job failure,
     * unless every host fails it.
     */
    private static void requireSafeHost(String hostname) throws Exception {
        SafeAddressValidator.requireSafeIfResolvable(hostname);
    }
}
