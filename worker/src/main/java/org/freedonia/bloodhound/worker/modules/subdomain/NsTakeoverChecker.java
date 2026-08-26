package org.freedonia.bloodhound.worker.modules.subdomain;

import java.net.InetAddress;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/**
 * Fetch side of NS-delegation takeover detection. Same shape as
 * {@link DanglingCnameChecker}/{@link CloudBucketChecker}: cheap for the
 * overwhelming majority of hostnames (no independent NS delegation at all,
 * or NS records matching no known cloud-DNS provider) since
 * {@link NsTakeoverDecisionLogic#matchProvider} is a pure local check done
 * before any network call; a confirmation DNS query only happens for the
 * small subset whose delegation actually points at a known provider.
 *
 * <p>Confirmation queries the claimed nameserver *directly* (bypassing the
 * public resolver entirely) for the subdomain's SOA record - the same
 * "does it answer authoritatively" mechanic
 * {@link org.freedonia.bloodhound.worker.modules.dns.DnsZoneFetcher} already
 * uses for the target's own apex, applied here per-subdomain against
 * specifically the cloud-provider nameservers that make a lame answer
 * exploitable. If any one of a subdomain's matched-provider nameservers
 * fails to answer authoritatively, that's treated as confirmed - a real
 * attacker only needs one of several NS records to be claimable, since
 * resolvers don't consistently prefer any particular one.
 */
class NsTakeoverChecker {

    record Result(boolean confirmedTakeover, String provider, String nameserver) {}

    private static final int POOL_SIZE = 10;
    private static final Duration TIMEOUT = Duration.ofSeconds(8);

    Map<String, Result> checkAll(Map<String, List<String>> hostnameToNameservers) {
        if (hostnameToNameservers.isEmpty()) {
            return Map.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, hostnameToNameservers.size()));
        try {
            Map<String, Future<Result>> futures = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> entry : hostnameToNameservers.entrySet()) {
                futures.put(entry.getKey(), pool.submit(() -> checkOne(entry.getKey(), entry.getValue())));
            }
            Map<String, Result> results = new LinkedHashMap<>();
            for (Map.Entry<String, Future<Result>> entry : futures.entrySet()) {
                try {
                    results.put(entry.getKey(), entry.getValue().get(30, TimeUnit.SECONDS));
                } catch (Exception ignored) {
                    // One host's checks timing out shouldn't be reported as a false positive or
                    // fail the whole batch - same tolerant philosophy as the other subdomain checkers.
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private Result checkOne(String hostname, List<String> nameservers) {
        for (String ns : nameservers) {
            Optional<NsTakeoverDecisionLogic.Match> match = NsTakeoverDecisionLogic.matchProvider(ns);
            if (match.isPresent() && !respondsAuthoritatively(hostname, ns)) {
                return new Result(true, match.get().provider().name(), ns);
            }
        }
        return new Result(false, null, null);
    }

    /** Same mechanic as DnsZoneFetcher#respondsAuthoritatively - a real SOA answer for the exact zone means it's genuinely still hosted there. */
    private boolean respondsAuthoritatively(String hostname, String nsHostname) {
        try {
            InetAddress nsAddress = InetAddress.getByName(nsHostname);
            // SSRF guard: this nameserver hostname came from the target's own DNS delegation,
            // never validated the way a user-submitted target hostname is - see
            // SafeAddressValidator's javadoc.
            if (SafeAddressValidator.isUnsafeToConnect(nsAddress)) {
                // Can't safely query it either way - report as "responds fine" (suppresses the
                // finding) rather than risk a false positive from a check we never actually ran.
                return true;
            }
            SimpleResolver directResolver = new SimpleResolver(nsAddress.getHostAddress());
            directResolver.setTimeout(TIMEOUT);
            Lookup lookup = new Lookup(hostname, Type.SOA);
            lookup.setResolver(directResolver);
            Record[] records = lookup.run();
            return records != null && records.length > 0 && records[0] instanceof SOARecord;
        } catch (Exception e) {
            return false;
        }
    }
}
