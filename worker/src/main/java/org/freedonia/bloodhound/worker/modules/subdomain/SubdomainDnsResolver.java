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
 */
public class SubdomainDnsResolver {

    private static final String PUBLIC_RESOLVER = "1.1.1.1";
    private static final int POOL_SIZE = 20;
    private static final Duration PER_LOOKUP_TIMEOUT = Duration.ofSeconds(5);

    private final Resolver resolver;

    public SubdomainDnsResolver() {
        try {
            SimpleResolver simpleResolver = new SimpleResolver(PUBLIC_RESOLVER);
            simpleResolver.setTimeout(Duration.ofSeconds(3));
            this.resolver = simpleResolver;
        } catch (UnknownHostException e) {
            throw new IllegalStateException("failed to configure DNS resolver " + PUBLIC_RESOLVER, e);
        }
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

    private String resolveCnameOne(String hostname) {
        try {
            Lookup lookup = new Lookup(hostname, Type.CNAME);
            lookup.setResolver(resolver);
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
        return ips;
    }

    private List<String> queryAddresses(String hostname, int type) {
        try {
            Lookup lookup = new Lookup(hostname, type);
            lookup.setResolver(resolver);
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
