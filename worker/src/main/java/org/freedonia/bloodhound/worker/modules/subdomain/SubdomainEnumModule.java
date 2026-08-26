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
 * Milestone 6b), resolves current IPs, CNAME targets, and NS delegation for
 * what it finds, runs dangling-CNAME/takeover confirmation plus
 * cloud-storage-bucket public-listing confirmation (see CloudBucketChecker -
 * same CNAME data, a different check: "unclaimed" vs "claimed but publicly
 * readable") plus NS-delegation takeover confirmation (see NsTakeoverChecker
 * - a third, more severe variant: a subdomain delegated as its own DNS zone,
 * not just CNAME'd to a resource), and hands the full raw list to
 * central-server via ModuleResult.rawMetadata() rather than emitting
 * "new subdomain" findings itself - "is this hostname new" is a
 * database-backed question only central-server can answer (see
 * SubdomainIngestionService), so this module stays a stateless
 * fetch-and-aggregate step, matching the fetch/parse testability split used
 * by the other Tier 1 modules. Dangling-CNAME, bucket-listing, and
 * NS-takeover confirmation, by contrast, need no cross-run state - each is a
 * pure function of this run's live DNS + HTTP data - so they're computed
 * here and reported directly per-hostname.
 *
 * A source failing entirely (e.g. crt.sh's documented flakiness, or
 * subfinder's binary being unavailable) does not fail the module as long as
 * at least one other source produced results; the module only fails if
 * every configured source failed.
 */
@Component
public class SubdomainEnumModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(SubdomainEnumModule.class);

    private final List<SubdomainSource> sources;
    private final SubdomainDnsResolver dnsResolver;
    private final DanglingCnameChecker cnameChecker;
    private final CloudBucketChecker bucketChecker;
    private final NsTakeoverChecker nsTakeoverChecker;

    public SubdomainEnumModule(List<SubdomainSource> sources) {
        this.sources = sources;
        this.dnsResolver = new SubdomainDnsResolver();
        this.cnameChecker = new DanglingCnameChecker();
        this.bucketChecker = new CloudBucketChecker();
        this.nsTakeoverChecker = new NsTakeoverChecker();
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
        Map<String, String> cnames = dnsResolver.resolveCnames(discovered);
        Map<String, DanglingCnameChecker.Result> cnameChecks = cnameChecker.checkAll(cnames);
        Map<String, CloudBucketChecker.Result> bucketChecks = bucketChecker.checkAll(cnames);
        Map<String, List<String>> nameservers = dnsResolver.resolveNameServers(discovered);
        Map<String, NsTakeoverChecker.Result> nsTakeoverChecks = nsTakeoverChecker.checkAll(nameservers);

        List<Map<String, Object>> subdomainEntries = new ArrayList<>();
        for (String hostname : discovered) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("hostname", hostname);
            entry.put("ipAddresses", resolvedIps.getOrDefault(hostname, List.of()));
            entry.put("source", String.join(",", merged.get(hostname)));

            DanglingCnameChecker.Result cnameCheck = cnameChecks.get(hostname);
            if (cnameCheck != null) {
                entry.put("cnameTarget", cnameCheck.cnameTarget());
                entry.put("danglingConfirmed", cnameCheck.confirmedDangling());
                entry.put("danglingService", cnameCheck.matchedService());
            }

            CloudBucketChecker.Result bucketCheck = bucketChecks.get(hostname);
            if (bucketCheck != null) {
                entry.put("bucketProvider", bucketCheck.provider().name());
                entry.put("bucketCheckUrl", bucketCheck.checkUrl());
                entry.put("bucketPubliclyListable", bucketCheck.publiclyListable());
            }

            NsTakeoverChecker.Result nsTakeoverCheck = nsTakeoverChecks.get(hostname);
            if (nsTakeoverCheck != null && nsTakeoverCheck.confirmedTakeover()) {
                entry.put("nsTakeoverConfirmed", true);
                entry.put("nsTakeoverProvider", nsTakeoverCheck.provider());
                entry.put("nsTakeoverNameserver", nsTakeoverCheck.nameserver());
            }
            subdomainEntries.add(entry);
        }

        return new ModuleResult(List.of(), Map.of("subdomains", subdomainEntries, "totalDiscovered", merged.size()));
    }
}
