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
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
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

    /**
     * A live false positive (a genuinely live, correctly-configured Route53 zone flagged as
     * dangling - confirmed by direct nameserver queries returning an authoritative SOA answer from
     * every delegated nameserver) traced back to this method previously going through dnsjava's
     * higher-level {@code Lookup} class and treating a {@code null}/empty result as "not
     * authoritative". {@code Lookup.run()} collapses REFUSED, SERVFAIL, a timeout, and any other
     * network-level failure into the same {@code null} - so a transient hiccup querying one of
     * several nameservers was as good as a confirmed takeover, at CRITICAL severity.
     *
     * <p>The actual, specific signature of "this cloud DNS provider has no zone configured here"
     * (confirmed live against Route53, and consistent with how Azure DNS/Google Cloud DNS/
     * DigitalOcean's own authoritative-only nameservers behave for a query outside anything they
     * host) is an explicit {@code REFUSED} response - these providers never do open/recursive
     * resolution, so a query for a zone they don't have is rejected outright, not answered with
     * NXDOMAIN or silence. Querying directly via {@code Message}/{@code Resolver#send} (not
     * {@code Lookup}) makes that Rcode directly inspectable, rather than inferring it from whether
     * dnsjava happened to hand back a non-empty record array. Only that explicit REFUSED is treated
     * as confirmation; a real SOA answer, any other Rcode, and - critically - any exception
     * (timeout, network error, malformed response) all fall through to "can't confirm a takeover
     * here", same "don't let an inconclusive check produce a CRITICAL false positive" reasoning the
     * SSRF-guard branch above already uses.
     */
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
            Name name = Name.fromString(hostname, Name.root);
            Record question = Record.newRecord(name, Type.SOA, DClass.IN);
            Message response = directResolver.send(Message.newQuery(question));
            return response.getRcode() != Rcode.REFUSED;
        } catch (Exception e) {
            return true;
        }
    }
}
