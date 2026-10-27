package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Aggregates every configured SubdomainSource (crt.sh + subfinder as of
 * Milestone 6b, katana's js-crawl mode added afterward - see KatanaCliSource)
 * and resolves current IPs for what it finds, handing the full raw list to
 * central-server via ModuleResult.rawMetadata() rather than emitting
 * "new subdomain" findings itself - "is this hostname new" is a
 * database-backed question only central-server can answer (see
 * SubdomainIngestionService), so this module stays a stateless
 * fetch-and-aggregate step, matching the fetch/parse testability split used
 * by the other Tier 1 modules.
 *
 * <p>Deliberately does NOT run dangling-CNAME, cloud-storage-bucket
 * public-listing, or NS-delegation takeover confirmation (DanglingCnameChecker/
 * CloudBucketChecker/NsTakeoverChecker) any more - a security/legal review
 * found all three make an active HTTP GET or direct-to-nameserver DNS query
 * against infrastructure a COMPETITOR/UNAUTHORIZED target's own subdomain or
 * cloud resources point at, a materially different risk to run
 * unconditionally than this module's own passive discovery + IP resolution.
 * See {@code SubdomainTakeoverCheckModule} (Tier 2, authorization-gated, one
 * job per already-discovered host) for where those three checkers moved -
 * {@link #excludeCnamedHosts} stays here as a small, well-tested pure
 * utility that module now calls into.
 *
 * <p>A source failing entirely (e.g. crt.sh's documented flakiness, or
 * subfinder's binary being unavailable) does not fail the module as long as
 * at least one other source produced results; the module only fails if
 * every configured source failed.
 */
@Component
public class SubdomainEnumModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(SubdomainEnumModule.class);

    private final List<SubdomainSource> sources;
    private final SubdomainDnsResolver dnsResolver;

    public SubdomainEnumModule(List<SubdomainSource> sources) {
        this.sources = sources;
        this.dnsResolver = new SubdomainDnsResolver();
    }

    @Override
    public String moduleType() {
        return "SUBDOMAIN_ENUM";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        Map<String, List<String>> perSourceResults = new LinkedHashMap<>();
        List<String> failures = new ArrayList<>();
        for (SubdomainSource source : sources) {
            try {
                perSourceResults.put(source.sourceName(), source.discover(context.hostname()));
            } catch (Exception e) {
                failures.add(source.sourceName() + ": " + e.getMessage());
                log.warn("subdomain source {} failed for {}: {}", source.sourceName(), context.hostname(), e.getMessage());
            }
        }
        // ExternalCliSubdomainSource-backed sources never throw (a missing/failing
        // binary is swallowed there and reported as an empty result, so other
        // sources aren't penalized for one tool being unavailable); only a
        // source like CrtShSource that treats fetch failure as a hard error
        // lands in `failures`. perSourceResults being empty means every
        // configured source failed outright - that's the only case worth
        // failing the whole module for.
        if (perSourceResults.isEmpty()) {
            throw new ScanModuleException(
                    "subdomain discovery failed for " + context.hostname() + " - every source failed: " + failures);
        }

        Map<String, TreeSet<String>> merged = SubdomainMerge.merge(perSourceResults);
        List<String> discovered = merged.keySet().stream().sorted().toList();

        Map<String, List<String>> resolvedIps = dnsResolver.resolveAll(discovered);

        List<Map<String, Object>> subdomainEntries = new ArrayList<>();
        for (String hostname : discovered) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("hostname", hostname);
            entry.put("ipAddresses", resolvedIps.getOrDefault(hostname, List.of()));
            entry.put("source", String.join(",", merged.get(hostname)));
            subdomainEntries.add(entry);
        }

        return new ModuleResult(List.of(), Map.of("subdomains", subdomainEntries, "totalDiscovered", merged.size()));
    }

    /**
     * Pure filter, split out purely so it's unit-testable without a real DNS resolver: a
     * hostname with a resolved CNAME is excluded from NS-delegation takeover checking, since a
     * name with a CNAME record cannot also carry an NS RRset at that same owner name (RFC 1035
     * S3.6.2) - any such hostname is therefore not a candidate for real NS delegation at all.
     */
    static List<String> excludeCnamedHosts(List<String> discovered, Map<String, String> cnames) {
        return discovered.stream().filter(hostname -> !cnames.containsKey(hostname)).toList();
    }
}
