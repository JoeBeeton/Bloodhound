package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.springframework.stereotype.Component;

/**
 * Tier 2: live takeover-confirmation checks for a single subdomain - dangling-CNAME
 * ({@link DanglingCnameChecker}), publicly-listable cloud-storage-bucket
 * ({@link CloudBucketChecker}), and dangling NS-delegation ({@link NsTakeoverChecker})
 * confirmation. Split out of SUBDOMAIN_ENUM (which stays Tier 1 and keeps doing passive discovery
 * only - crt.sh/subfinder/Katana crawl plus IP resolution) because, unlike discovery, all three
 * of these make an active HTTP GET or direct-to-nameserver DNS query against infrastructure a
 * COMPETITOR/UNAUTHORIZED target's own subdomain or cloud resources point at - the same
 * "not genuinely passive" reasoning that moved EXPOSURE_CHECKS to Tier 2 (see
 * {@code ScanRunService#TIER1_MODULE_TYPES}'s own comment). Only ever dispatched via
 * TargetController's authorization-gated deep-scan endpoint, one job per selected host (see
 * {@code ScanRunService#createDeepScan}), exactly like PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/
 * NUCLEI_SCAN/EXPOSURE_CHECKS.
 *
 * <p>Resolves this one host's own CNAME/NS records itself rather than reusing SUBDOMAIN_ENUM's
 * already-resolved data - the worker has no database access of its own to look that back up (see
 * {@link PayloadSubdomains}'s own javadoc), and a direct re-resolution is cheap for a single host
 * run as its own separate job. Emits the exact same three rule_ids/severities/descriptions
 * {@code SubdomainIngestionService} used to synthesize from SUBDOMAIN_ENUM's rawMetadata, as
 * plain {@link RawFinding}s now - these three are a pure, live-reconfirmed-every-run function of
 * this run's own checks (unlike SUBDOMAIN_NEW_UNEXPECTED/SUBDOMAIN_STALE_NOT_RESOLVING, which
 * stay there since they genuinely depend on database history), so they need no central-server
 * synthesis step and go through the ordinary finding-reconciliation path like any other module's
 * findings.
 */
@Component
public class SubdomainTakeoverCheckModule implements ScanModule {

    private final SubdomainDnsResolver dnsResolver = new SubdomainDnsResolver();
    private final DanglingCnameChecker cnameChecker = new DanglingCnameChecker();
    private final CloudBucketChecker bucketChecker = new CloudBucketChecker();
    private final NsTakeoverChecker nsTakeoverChecker = new NsTakeoverChecker();

    @Override
    public String moduleType() {
        return "SUBDOMAIN_TAKEOVER_CHECK";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        String host = PayloadSubdomains.singleHost(context);
        List<RawFinding> findings = new ArrayList<>();

        Map<String, String> cnames = dnsResolver.resolveCnames(List.of(host));

        DanglingCnameChecker.Result cnameCheck = cnameChecker.checkAll(cnames).get(host);
        if (cnameCheck != null && cnameCheck.confirmedDangling()) {
            findings.add(new RawFinding(
                    "SUBDOMAIN_DANGLING_CNAME",
                    Severity.CRITICAL,
                    Category.SUBDOMAIN_HYGIENE,
                    "Dangling CNAME - possible subdomain takeover",
                    "This subdomain's CNAME points to a " + cnameCheck.matchedService() + " resource that "
                            + "responded as unclaimed, allowing an attacker to claim it and serve content from "
                            + "this subdomain.",
                    host,
                    Map.of("cnameTarget", cnameCheck.cnameTarget(), "service", cnameCheck.matchedService())));
        }

        CloudBucketChecker.Result bucketCheck = bucketChecker.checkAll(cnames).get(host);
        if (bucketCheck != null && bucketCheck.publiclyListable()) {
            String provider = bucketCheck.provider().name();
            findings.add(new RawFinding(
                    "EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING",
                    Severity.CRITICAL,
                    Category.EXPOSURE,
                    "Publicly listable cloud storage bucket",
                    "This subdomain's CNAME points directly at a " + provider + " storage bucket that allows "
                            + "anyone to list its full contents without authentication.",
                    host,
                    Map.of("provider", provider, "checkUrl", bucketCheck.checkUrl())));
        }

        // See SubdomainEnumModule#excludeCnamedHosts' own javadoc for why a CNAME'd hostname is
        // never NS-eligible at all.
        List<String> nsEligibleHosts = SubdomainEnumModule.excludeCnamedHosts(List.of(host), cnames);
        if (!nsEligibleHosts.isEmpty()) {
            Map<String, List<String>> nameservers = dnsResolver.resolveNameServers(nsEligibleHosts);
            NsTakeoverChecker.Result nsTakeoverCheck = nsTakeoverChecker.checkAll(nameservers).get(host);
            if (nsTakeoverCheck != null && nsTakeoverCheck.confirmedTakeover()) {
                findings.add(new RawFinding(
                        "SUBDOMAIN_NS_DELEGATION_TAKEOVER",
                        Severity.CRITICAL,
                        Category.SUBDOMAIN_HYGIENE,
                        "Dangling NS delegation - possible subdomain takeover",
                        "This subdomain is delegated to " + nsTakeoverCheck.provider() + " nameserver "
                                + nsTakeoverCheck.nameserver() + ", which does not answer authoritatively for it - "
                                + "the corresponding hosted zone appears to be deprovisioned or never created, and "
                                + "anyone who notices can claim it.",
                        host,
                        Map.of("provider", nsTakeoverCheck.provider(), "nameserver", nsTakeoverCheck.nameserver())));
            }
        }

        return new ModuleResult(findings, Map.of("host", host));
    }
}
