package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.HostFanOut;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.freedonia.bloodhound.worker.modules.subdomain.SubdomainDnsResolver;
import org.springframework.stereotype.Component;

/**
 * Passive technology-stack and hosting-provider fingerprinting for the
 * target's root hostname plus its already-discovered subdomains (handed over
 * capped in the job payload by ScanRunService, since this module has no
 * database access of its own - see ScanContext.jobPayload()). Produces no
 * findings; this is informational context surfaced directly in the UI, not a
 * severity-bearing signal.
 *
 * <p>Uses {@link HostFanOut#runPerHost} for the same host-count-based failure
 * semantics as the other fanned-out Tier 1 modules: an unreachable apex is
 * expected and tolerated as long as some subdomains resolve (a target can
 * legitimately have no A/AAAA record at the root while its real presence
 * lives entirely on subdomains), and the job only fails when literally every
 * attempted host - root included - was unreachable.
 */
@Component
public class FingerprintModule implements ScanModule {

    private static final int SUBDOMAIN_CAP = 40;
    private static final int POOL_SIZE = 10;
    private static final long PER_HOST_TIMEOUT_SECONDS = 20;

    private final TechFetcher techFetcher = new TechFetcher();
    private final AsnFetcher asnFetcher = new AsnFetcher();

    @Override
    public String moduleType() {
        return "TECH_FINGERPRINT";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        List<String> subdomains = PayloadSubdomains.from(context).stream().limit(SUBDOMAIN_CAP).toList();

        Set<String> hostnames = new LinkedHashSet<>();
        hostnames.add(context.hostname());
        hostnames.addAll(subdomains);

        // A/AAAA resolution done as one batched, internally-concurrent call
        // (SubdomainDnsResolver already bounds and parallelizes this) rather
        // than per-hostname inside the fetch loop below.
        Map<String, List<String>> ipsByHost = new SubdomainDnsResolver().resolveAll(hostnames);

        HostFanOut.ValueResult<Map<String, Object>> result = HostFanOut.runPerHost(
                context.hostname(),
                subdomains,
                SUBDOMAIN_CAP,
                POOL_SIZE,
                PER_HOST_TIMEOUT_SECONDS,
                hostname -> fingerprintOne(hostname, ipsByHost.getOrDefault(hostname, List.of())));

        return new ModuleResult(List.<RawFinding>of(), Map.of("fingerprints", result.perHostResults()));
    }

    private Map<String, Object> fingerprintOne(String hostname, List<String> ips) throws Exception {
        TechFetchResult fetched = techFetcher.fetch(hostname);
        List<Technology> technologies = new java.util.ArrayList<>(TechDecisionLogic.decide(fetched));

        // A second, targeted request - only made once WordPress is already confirmed from the
        // homepage fetch above, so this doesn't cost every non-WordPress host an extra request -
        // see TechFetcher#fetchWpJson for why this reliably finds installed plugins even on sites
        // that strip every other WordPress signal.
        if (technologies.stream().anyMatch(t -> t.name().equals("WordPress"))) {
            technologies.addAll(WordPressRestApiDecisionLogic.decide(techFetcher.fetchWpJson(hostname)));
        }

        String hostingProvider = null;
        String hostingAsn = null;
        String hostingAsnOrg = null;
        // Tries every resolved IP (both A and AAAA - see SubdomainDnsResolver)
        // in order, not just the first, and stops at the first one that
        // actually yields ASN data. Previously this only ever tried ips.get(0),
        // which - since A records are queried before AAAA - meant an
        // IPv6-only host got no hosting-provider data at all, and a
        // dual-stack host's data always reflected its IPv4 hosting even if
        // that particular address's ASN lookup happened to come back empty.
        for (String ip : ips) {
            AsnLookupResult asn = asnFetcher.lookup(ip);
            if (asn.asn() != null) {
                hostingAsn = asn.asn();
                hostingAsnOrg = asn.asnOrg();
                hostingProvider = HostingProviderMapper.toFriendlyName(asn.asnOrg());
                break;
            }
        }

        Map<String, Object> entry = new java.util.LinkedHashMap<>();
        entry.put("hostname", hostname);
        entry.put(
                "technologies",
                technologies.stream()
                        .map(t -> {
                            Map<String, Object> tech = new java.util.LinkedHashMap<>();
                            tech.put("name", t.name());
                            tech.put("category", t.category());
                            if (t.version() != null) {
                                tech.put("version", t.version());
                            }
                            return tech;
                        })
                        .toList());
        if (hostingProvider != null) entry.put("hostingProvider", hostingProvider);
        if (hostingAsn != null) entry.put("hostingAsn", hostingAsn);
        if (hostingAsnOrg != null) entry.put("hostingAsnOrg", hostingAsnOrg);
        return entry;
    }
}
