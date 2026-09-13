package org.freedonia.bloodhound.worker.modules.common;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;

/**
 * One DNS lookup path for the fetchers that used to each hardcode Cloudflare's 1.1.1.1 as
 * their only resolver (DnsRecordFetcher, DnsZoneFetcher, AsnFetcher - SubdomainDnsResolver
 * grew its own copy of this fallback first, see its javadoc for the original diagnosis).
 *
 * <p>Two things the old pattern got wrong, both found by a rules audit of the live findings:
 *
 * <ol>
 *   <li>No fallback. On a host whose VPN/firewall policy blocks direct port-53 traffic to
 *       public resolvers (this deployment: every query to 1.1.1.1/8.8.8.8/9.9.9.9 is refused
 *       outright, TCP and UDP), the only resolver that works is the platform one - Docker's
 *       embedded 127.0.0.11 forwarding to the host's stub. The original reason for avoiding it
 *       (SERVFAIL on github.com's large TXT set, NOTIMP on DNSKEY) no longer reproduces: probed
 *       in-container, it now returns all 24 github.com TXT records and cloudflare.com's DNSKEYs
 *       correctly over both UDP and TCP.
 *   <li>Failure was indistinguishable from absence. {@code Lookup.run()} returns null for
 *       "network error" and for "no such record" alike, so an unreachable resolver made every
 *       DNS-posture rule fire at once: 24 of the 25 open DNS findings in this deployment were
 *       SPF/DMARC/CAA/DNSSEC "missing" on domains (barclays.co.uk, americanexpress.com...) that
 *       plainly publish all of them. {@link Answer#answered()} exposes what dnsjava does know -
 *       SUCCESSFUL, HOST_NOT_FOUND and TYPE_NOT_FOUND are real answers; UNRECOVERABLE and
 *       TRY_AGAIN are not - so callers can refuse to turn "unknown" into "missing".
 * </ol>
 */
public final class FallbackDnsLookup {

    private static final Logger log = LoggerFactory.getLogger(FallbackDnsLookup.class);
    private static final String PUBLIC_RESOLVER = "1.1.1.1";
    private static final Duration TIMEOUT = Duration.ofSeconds(4);

    /** {@code answered} is false only when neither resolver produced any authoritative-or-negative answer. */
    public record Answer(List<Record> records, boolean answered) {
        public static final Answer FAILED = new Answer(List.of(), false);

        public boolean isEmpty() {
            return records.isEmpty();
        }
    }

    private final Resolver primary;
    private final Resolver system;

    /** @param tcp query over TCP (no response-size limit - needed for large apex TXT sets) */
    public FallbackDnsLookup(boolean tcp) {
        this.primary = configure(newPublicResolver(), tcp);
        this.system = configure(newSystemResolver(), tcp);
    }

    private static SimpleResolver newPublicResolver() {
        try {
            return new SimpleResolver(PUBLIC_RESOLVER);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("failed to configure DNS resolver " + PUBLIC_RESOLVER, e);
        }
    }

    /** Whatever this environment's platform DNS config points at - null if dnsjava can't find one at all. */
    private static SimpleResolver newSystemResolver() {
        try {
            return new SimpleResolver();
        } catch (UnknownHostException | IllegalArgumentException e) {
            log.warn("no system DNS resolver available for fallback: {}", e.getMessage());
            return null;
        }
    }

    private static Resolver configure(SimpleResolver resolver, boolean tcp) {
        if (resolver == null) {
            return null;
        }
        resolver.setTCP(tcp);
        resolver.setTimeout(TIMEOUT);
        return resolver;
    }

    public Answer lookup(String name, int type) {
        Answer fromPrimary = run(name, type, primary);
        if (fromPrimary.answered() || system == null) {
            return fromPrimary;
        }
        Answer fromSystem = run(name, type, system);
        if (!fromSystem.answered()) {
            log.warn("DNS lookup {} type {} failed on both the public and the system resolver", name, type);
        }
        return fromSystem;
    }

    private static Answer run(String name, int type, Resolver resolver) {
        if (resolver == null) {
            return Answer.FAILED;
        }
        try {
            Lookup lookup = new Lookup(name, type);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            if (!isDefinitive(lookup.getResult())) {
                return Answer.FAILED;
            }
            return new Answer(records == null ? List.of() : List.of(records), true);
        } catch (TextParseException | IllegalArgumentException e) {
            // Malformed name ("_dmarc." + an already-invalid hostname) - a definitive "no records",
            // not a resolver problem.
            return new Answer(List.of(), true);
        }
    }

    /**
     * SUCCESSFUL, HOST_NOT_FOUND (NXDOMAIN) and TYPE_NOT_FOUND (NODATA) are the resolver telling
     * us something about the name; UNRECOVERABLE (network error, SERVFAIL, REFUSED) and TRY_AGAIN
     * (timeout) are it telling us nothing.
     */
    static boolean isDefinitive(int lookupResult) {
        return lookupResult == Lookup.SUCCESSFUL
                || lookupResult == Lookup.HOST_NOT_FOUND
                || lookupResult == Lookup.TYPE_NOT_FOUND;
    }
}
