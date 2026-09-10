package org.freedonia.bloodhound.worker.modules.subdomain;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/**
 * Resolves A/AAAA records for a batch of discovered subdomains, bounded and
 * concurrent since there can be dozens to hundreds of hostnames per target.
 * Uses the same public resolver as DnsPostureModule (Cloudflare 1.1.1.1) for
 * the same reason - reliable answers regardless of the deployment
 * environment's local stub resolver - but over UDP rather than TCP: A/AAAA
 * responses are small (unlike the large TXT record sets that forced TCP
 * there), so plain UDP is fine and considerably faster across many parallel
 * lookups.
 *
 * <p>A live false negative: every subdomain of a real target came back with
 * an empty IP list here - marking all of them inactive and leaving
 * HostFanOut with nothing to scan but the (legitimately non-resolving) apex
 * - even though one of those subdomains demonstrably resolves (confirmed
 * both via the host's own normal resolver and via this exact container's
 * embedded DNS at 127.0.0.11/getent). Root cause: this machine's VPN routes
 * 1.1.1.1 through its tunnel and applies DNS-leak-protection to it, which
 * silently drops direct UDP/53 queries to public resolvers - the very thing
 * this class exists to bypass local-resolver problems with. dnsjava's
 * {@code Lookup} collapses that into the same empty result as a genuine
 * NXDOMAIN, so there was no way to tell "really no record" from "that
 * specific query got eaten in transit" from here. {@link #systemResolver} is
 * a second attempt against whatever this environment's own default resolver
 * chain resolves to (its own doc comment on why that's viable now, unlike
 * being the sole resolver) - only consulted when the direct-to-1.1.1.1
 * attempt comes back empty, so a genuinely correct NXDOMAIN just costs one
 * harmless extra query, while a leak-protection-eaten query gets a real
 * second chance instead of silently marking a live host as dead.
 */
public class SubdomainDnsResolver {

    private static final String PUBLIC_RESOLVER = "1.1.1.1";
    private static final int POOL_SIZE = 20;
    private static final Duration PER_LOOKUP_TIMEOUT = Duration.ofSeconds(5);

    private final Resolver resolver;
    private final Resolver systemResolver;

    public SubdomainDnsResolver() {
        try {
            SimpleResolver simpleResolver = new SimpleResolver(PUBLIC_RESOLVER);
            simpleResolver.setTimeout(Duration.ofSeconds(3));
            this.resolver = simpleResolver;
        } catch (UnknownHostException e) {
            throw new IllegalStateException("failed to configure DNS resolver " + PUBLIC_RESOLVER, e);
        }
        // No-arg SimpleResolver reads whatever this environment's own platform DNS config points
        // at (this container's /etc/resolv.conf - Docker's embedded 127.0.0.11 here) - see this
        // class's own doc comment for why a second, independent resolver is now worth having
        // rather than trusting the direct public-resolver query alone.
        Resolver fallback;
        try {
            SimpleResolver systemSimpleResolver = new SimpleResolver();
            systemSimpleResolver.setTimeout(Duration.ofSeconds(3));
            fallback = systemSimpleResolver;
        } catch (UnknownHostException e) {
            fallback = null;
        }
        this.systemResolver = fallback;
    }

    public Map<String, List<String>> resolveAll(Collection<String> hostnames) {
        if (hostnames.isEmpty()) {
            return Map.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, hostnames.size()));
        try {
            Map<String, Future<List<String>>> futures = new LinkedHashMap<>();
            for (String hostname : hostnames) {
                futures.put(hostname, pool.submit(() -> resolveOne(hostname)));
            }
            Map<String, List<String>> results = new LinkedHashMap<>();
            for (Map.Entry<String, Future<List<String>>> entry : futures.entrySet()) {
                try {
                    results.put(entry.getKey(), entry.getValue().get(PER_LOOKUP_TIMEOUT.toSeconds(), TimeUnit.SECONDS));
                } catch (Exception e) {
                    results.put(entry.getKey(), List.of());
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * Resolves CNAME targets for a batch of hostnames, same bounded-pool
     * shape as {@link #resolveAll}. Most hostnames have no CNAME at all
     * (plain A/AAAA records) - those simply come back absent from the map,
     * not as an error.
     */
    public Map<String, String> resolveCnames(Collection<String> hostnames) {
        if (hostnames.isEmpty()) {
            return Map.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, hostnames.size()));
        try {
            Map<String, Future<String>> futures = new LinkedHashMap<>();
            for (String hostname : hostnames) {
                futures.put(hostname, pool.submit(() -> resolveCnameOne(hostname)));
            }
            Map<String, String> results = new LinkedHashMap<>();
            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                try {
                    String cname = entry.getValue().get(PER_LOOKUP_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
                    if (cname != null) {
                        results.put(entry.getKey(), cname);
                    }
                } catch (Exception ignored) {
                    // no CNAME, timed out, or resolution failed - treated the same as "no CNAME".
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * Resolves NS records for a batch of hostnames, same bounded-pool shape
     * as {@link #resolveAll}. Most subdomains have none at all - independent
     * NS delegation is deliberate and relatively rare (a subdomain handed
     * off to its own separately-hosted zone, e.g. for a third-party SaaS
     * integration or organizational separation) - those simply come back
     * absent from the map, not as an error.
     */
    public Map<String, List<String>> resolveNameServers(Collection<String> hostnames) {
        if (hostnames.isEmpty()) {
            return Map.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, hostnames.size()));
        try {
            Map<String, Future<List<String>>> futures = new LinkedHashMap<>();
            for (String hostname : hostnames) {
                futures.put(hostname, pool.submit(() -> resolveNsOne(hostname)));
            }
            Map<String, List<String>> results = new LinkedHashMap<>();
            for (Map.Entry<String, Future<List<String>>> entry : futures.entrySet()) {
                try {
                    List<String> ns = entry.getValue().get(PER_LOOKUP_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
                    if (!ns.isEmpty()) {
                        results.put(entry.getKey(), ns);
                    }
                } catch (Exception ignored) {
                    // no NS records, timed out, or resolution failed - treated the same as "no NS delegation".
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private List<String> resolveNsOne(String hostname) {
        List<String> primary = nsRecords(hostname, resolver);
        if (!primary.isEmpty() || systemResolver == null) {
            return primary;
        }
        return nsRecords(hostname, systemResolver);
    }

    private List<String> nsRecords(String hostname, Resolver r) {
        try {
            Lookup lookup = new Lookup(hostname, Type.NS);
            lookup.setResolver(r);
            Record[] records = lookup.run();
            if (records == null) {
                return List.of();
            }
            List<String> nameservers = new ArrayList<>();
            for (Record record : records) {
                if (record instanceof NSRecord ns) {
                    nameservers.add(ns.getTarget().toString(true));
                }
            }
            return nameservers;
        } catch (Exception e) {
            return List.of();
        }
    }

    private String resolveCnameOne(String hostname) {
        String primary = cnameRecord(hostname, resolver);
        if (primary != null || systemResolver == null) {
            return primary;
        }
        return cnameRecord(hostname, systemResolver);
    }

    private String cnameRecord(String hostname, Resolver r) {
        try {
            Lookup lookup = new Lookup(hostname, Type.CNAME);
            lookup.setResolver(r);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                return null;
            }
            return ((CNAMERecord) records[0]).getTarget().toString(true);
        } catch (Exception e) {
            return null;
        }
    }

    private List<String> resolveOne(String hostname) {
        List<String> ips = new ArrayList<>(queryAddresses(hostname, Type.A));
        ips.addAll(queryAddresses(hostname, Type.AAAA));
        if (!ips.isEmpty() || systemResolver == null) {
            return ips;
        }
        // Direct-to-1.1.1.1 came back with nothing for both record types - see this class's own
        // doc comment: that's ambiguous between "really nothing here" and "that query got eaten
        // in transit", so it's worth one more attempt against this environment's own resolver
        // before concluding the host is unreachable.
        List<String> fallbackIps = new ArrayList<>(addressRecords(hostname, Type.A, systemResolver));
        fallbackIps.addAll(addressRecords(hostname, Type.AAAA, systemResolver));
        return fallbackIps;
    }

    private List<String> queryAddresses(String hostname, int type) {
        return addressRecords(hostname, type, resolver);
    }

    private List<String> addressRecords(String hostname, int type, Resolver r) {
        try {
            Lookup lookup = new Lookup(hostname, type);
            lookup.setResolver(r);
            Record[] records = lookup.run();
            if (records == null) {
                return List.of();
            }
            List<String> ips = new ArrayList<>();
            for (Record record : records) {
                if (record instanceof ARecord a) {
                    ips.add(a.getAddress().getHostAddress());
                } else if (record instanceof AAAARecord aaaa) {
                    ips.add(aaaa.getAddress().getHostAddress());
                }
            }
            return ips;
        } catch (Exception e) {
            return List.of();
        }
    }
}
