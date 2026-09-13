package org.freedonia.bloodhound.server.subdomain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The one module-type-specific branch in result ingestion: a SUBDOMAIN_ENUM
 * job's rawMetadata carries the worker's full discovered-hostname list (with
 * resolved IPs, source provenance, and dangling-CNAME check results), not
 * findings - the module itself is stateless (fetch + dedupe + live
 * CNAME-takeover confirmation only) and has no idea what's "new" for this
 * target, so that comparison happens here against the subdomains table,
 * which this service also upserts. "New" findings are synthesized as
 * ordinary FindingPayloads and merged into the module's (normally empty)
 * reported-findings list before the standard FindingReconciler
 * dedup/resolution path runs on them - so a SUBDOMAIN_NEW_UNEXPECTED finding
 * that isn't reproduced next run (because the hostname is now already in the
 * table, so no longer "new") resolves itself automatically, matching its
 * Info/one-time-notification intent. SUBDOMAIN_DANGLING_CNAME findings work
 * the same way but their "still true" condition is different: the worker
 * re-confirms takeover-eligibility live on every scan (unlike "new", which
 * is a one-time database fact), so a dangling finding only keeps
 * reappearing - and only stays OPEN - for as long as it keeps being
 * reconfirmed run over run. EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING and
 * SUBDOMAIN_NS_DELEGATION_TAKEOVER both follow the same re-confirmed-live
 * pattern as SUBDOMAIN_DANGLING_CNAME, for the same reason - all three come
 * from a live check the worker redoes every run, not a one-time database
 * fact.
 */
@Service
public class SubdomainIngestionService {

    private static final Logger log = LoggerFactory.getLogger(SubdomainIngestionService.class);
    static final int RESOLVER_OUTAGE_MIN_HOSTS = 10;

    private final SubdomainRepository subdomainRepository;

    public SubdomainIngestionService(SubdomainRepository subdomainRepository) {
        this.subdomainRepository = subdomainRepository;
    }

    public List<FindingPayload> ingestAndSynthesizeFindings(
            UUID targetId, Map<String, Object> rawMetadata, List<FindingPayload> reportedFindings) {
        List<Map<String, Object>> discovered = extractSubdomainList(rawMetadata);
        Set<String> existingHostnames = subdomainRepository.findHostnames(targetId);
        Set<String> everResolved = subdomainRepository.findHostnamesEverResolved(targetId);
        boolean resolverOutage = looksLikeResolverOutage(discovered, everResolved);
        if (resolverOutage) {
            log.warn(
                    "SUBDOMAIN_ENUM for target {}: none of its {} previously-resolving hostnames resolved this run - "
                            + "treating as a resolver outage, not a mass decommission; no stale findings, liveness unchanged",
                    targetId,
                    everResolved.size());
        }

        List<FindingPayload> combined = new ArrayList<>(reportedFindings);
        for (Map<String, Object> entry : discovered) {
            String hostname = String.valueOf(entry.get("hostname"));
            if (hostname == null || hostname.isBlank() || "null".equals(hostname)) {
                continue;
            }
            List<String> ipAddresses = extractIpAddresses(entry.get("ipAddresses"));
            boolean isNew = !existingHostnames.contains(hostname);
            String source = entry.get("source") == null ? "UNKNOWN" : String.valueOf(entry.get("source"));
            boolean danglingConfirmed = Boolean.TRUE.equals(entry.get("danglingConfirmed"));
            String cnameTarget = entry.get("cnameTarget") == null ? null : String.valueOf(entry.get("cnameTarget"));
            String danglingService = entry.get("danglingService") == null ? null : String.valueOf(entry.get("danglingService"));

            subdomainRepository.upsert(
                    targetId, hostname, source, ipAddresses, danglingConfirmed ? cnameTarget : null, !resolverOutage);

            if (!resolverOutage && everResolved.contains(hostname) && ipAddresses.isEmpty()) {
                // A hostname that HAS resolved on a past run (last_resolved_at - see V54; not
                // merely "is in the table", which every never-resolving CT artifact also is)
                // and whose resolution attempt this run came back with nothing. Reproducing
                // every run keeps this OPEN via the normal reconciler dedup; a later scan where
                // it resolves again lets it resolve itself, exactly like
                // SUBDOMAIN_DANGLING_CNAME's "reconfirmed or it closes" behavior.
                combined.add(new FindingPayload(
                        "SUBDOMAIN_STALE_NOT_RESOLVING",
                        "LOW",
                        "SUBDOMAIN_HYGIENE",
                        "Subdomain no longer resolving",
                        "This subdomain was previously discovered and tracked but no longer resolves to any "
                                + "IP address, which may indicate abandoned infrastructure or a dangling DNS record.",
                        hostname,
                        Map.of("source", source)));
            }

            if (isNew) {
                combined.add(new FindingPayload(
                        "SUBDOMAIN_NEW_UNEXPECTED",
                        "INFO",
                        "SUBDOMAIN_HYGIENE",
                        "New subdomain discovered",
                        "A subdomain not previously observed for this target was discovered via passive "
                                + "enumeration (certificate transparency and/or passive OSINT sources).",
                        hostname,
                        Map.of("ipAddresses", ipAddresses, "source", source)));
            }

            if (danglingConfirmed) {
                combined.add(new FindingPayload(
                        "SUBDOMAIN_DANGLING_CNAME",
                        "CRITICAL",
                        "SUBDOMAIN_HYGIENE",
                        "Dangling CNAME - possible subdomain takeover",
                        "This subdomain's CNAME points to a " + danglingService + " resource that responded as "
                                + "unclaimed, allowing an attacker to claim it and serve content from this subdomain.",
                        hostname,
                        Map.of("cnameTarget", cnameTarget, "service", danglingService)));
            }

            boolean bucketPubliclyListable = Boolean.TRUE.equals(entry.get("bucketPubliclyListable"));
            if (bucketPubliclyListable) {
                String bucketProvider = String.valueOf(entry.get("bucketProvider"));
                String bucketCheckUrl = String.valueOf(entry.get("bucketCheckUrl"));
                combined.add(new FindingPayload(
                        "EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING",
                        "CRITICAL",
                        "EXPOSURE",
                        "Publicly listable cloud storage bucket",
                        "This subdomain's CNAME points directly at a " + bucketProvider + " storage bucket that "
                                + "allows anyone to list its full contents without authentication.",
                        hostname,
                        Map.of("provider", bucketProvider, "checkUrl", bucketCheckUrl)));
            }

            boolean nsTakeoverConfirmed = Boolean.TRUE.equals(entry.get("nsTakeoverConfirmed"));
            if (nsTakeoverConfirmed) {
                String nsProvider = String.valueOf(entry.get("nsTakeoverProvider"));
                String nsHostname = String.valueOf(entry.get("nsTakeoverNameserver"));
                combined.add(new FindingPayload(
                        "SUBDOMAIN_NS_DELEGATION_TAKEOVER",
                        "CRITICAL",
                        "SUBDOMAIN_HYGIENE",
                        "Dangling NS delegation - possible subdomain takeover",
                        "This subdomain is delegated to " + nsProvider + " nameserver " + nsHostname
                                + ", which does not answer authoritatively for it - the corresponding hosted zone "
                                + "appears to be deprovisioned or never created, and anyone who notices can claim it.",
                        hostname,
                        Map.of("provider", nsProvider, "nameserver", nsHostname)));
            }
        }
        return combined;
    }

    /**
     * A resolver outage looks like every host that has ever resolved going dark in the same run.
     * Real estates don't do that; broken DNS on the worker does (seen live: a VPN silently eating
     * the worker's DNS produced ~112,000 false "no longer resolving" findings on one target over
     * a few days, then ~112,000 resolutions once it was fixed). Below the floor there isn't
     * enough signal to call it either way, so the run is trusted.
     */
    static boolean looksLikeResolverOutage(List<Map<String, Object>> discovered, Set<String> everResolved) {
        int previouslyResolvingSeen = 0;
        int resolvedNow = 0;
        for (Map<String, Object> entry : discovered) {
            String hostname = String.valueOf(entry.get("hostname"));
            if (!everResolved.contains(hostname)) {
                continue;
            }
            previouslyResolvingSeen++;
            if (!extractIpAddresses(entry.get("ipAddresses")).isEmpty()) {
                resolvedNow++;
            }
        }
        return previouslyResolvingSeen >= RESOLVER_OUTAGE_MIN_HOSTS && resolvedNow == 0;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractSubdomainList(Map<String, Object> rawMetadata) {
        if (rawMetadata == null) {
            return List.of();
        }
        Object raw = rawMetadata.get("subdomains");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                result.add((Map<String, Object>) map);
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static List<String> extractIpAddresses(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<String> ips = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                ips.add(String.valueOf(item));
            }
        }
        return ips;
    }
}
