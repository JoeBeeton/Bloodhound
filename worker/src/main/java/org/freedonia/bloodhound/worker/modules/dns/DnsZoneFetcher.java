package org.freedonia.bloodhound.worker.modules.dns;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.worker.modules.common.FallbackDnsLookup;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.ZoneTransferException;
import org.xbill.DNS.ZoneTransferIn;

/**
 * Fetch side of the zone-level checks (AXFR + lame delegation) - see
 * DnsZoneDecisionLogic for interpretation. Split from DnsRecordFetcher
 * because these are per-nameserver active queries (resolve each NS, then
 * connect to it directly) rather than simple name/type lookups against the
 * one public resolver.
 */
public class DnsZoneFetcher {

    private static final Duration TIMEOUT = Duration.ofSeconds(6);

    /** NS/A discovery only - the AXFR and SOA probes below connect to each nameserver directly, by design. */
    private final FallbackDnsLookup dns = new FallbackDnsLookup(false);

    /**
     * {@code reachable} is false when this vantage point could not open TCP/53 to the nameserver
     * at all (connection refused, ICMP port-unreachable, timeout). Both probes below need a
     * direct conversation with the nameserver, so an unreachable one yields no evidence either
     * way - a rules audit found a deployment where outbound port 53 to arbitrary hosts is
     * blocked by VPN policy, and DNS_ZONE_TRANSFER_ALLOWED / DNS_NS_LAME_DELEGATION had silently
     * never been able to fire (zonetransfer.me, the canonical open-AXFR test zone, reported
     * "not allowed"). Surfaced in DnsPostureModule's result metadata so the coverage gap is
     * visible instead of indistinguishable from "checked, all fine".
     */
    public record NsCheckResult(
            String nameserver,
            boolean axfrAllowed,
            int axfrRecordCount,
            boolean answeredAuthoritatively,
            boolean reachable,
            boolean openResolver) {
        public NsCheckResult(String nameserver, boolean axfrAllowed, int axfrRecordCount, boolean answeredAuthoritatively) {
            this(nameserver, axfrAllowed, axfrRecordCount, answeredAuthoritatively, true, false);
        }

        public NsCheckResult(
                String nameserver, boolean axfrAllowed, int axfrRecordCount, boolean answeredAuthoritatively,
                boolean reachable) {
            this(nameserver, axfrAllowed, axfrRecordCount, answeredAuthoritatively, reachable, false);
        }
    }

    /**
     * @param includeActiveExploitProbes false to limit this call to the lame-delegation check
     *     only (a single direct SOA query) - used by Tier 1's {@code DnsPostureModule}, which must
     *     never actually attempt a zone transfer or an open-resolver recursion query against a
     *     COMPETITOR/UNAUTHORIZED target's nameservers, not merely suppress the resulting finding.
     *     {@code DnsZoneExploitModule} (Tier 2, authorization-gated) passes true to run the full
     *     AXFR + open-resolver probes alongside it.
     */
    public List<NsCheckResult> fetch(String hostname, boolean includeActiveExploitProbes) {
        List<String> nsHostnames = queryNsHostnames(hostname);
        List<NsCheckResult> results = new ArrayList<>();
        for (String ns : nsHostnames) {
            String nsIp = resolveA(ns);
            if (nsIp == null) {
                // Can't reach this NS at all from here - not evidence of anything, just skip it
                // rather than guessing at either a positive or negative finding.
                continue;
            }
            // A security review found respondsAuthoritatively/attemptAxfr connected straight to
            // nsIp with no SafeAddressValidator check at all - unlike every other outbound
            // connection this codebase makes. ns is attacker-influenceable (it's whatever NS
            // records the target's own DNS zone delegates to - by definition an external,
            // untrusted answer), so a target whose zone delegates to a nameserver hostname that
            // resolves to an internal address turns this into a real TCP/53 reachability oracle
            // into RFC1918/link-local space, the same class of gap NsTakeoverChecker already
            // guards against on its own, separate NS-resolution path. Treated the same as an
            // unreachable NS above - skipped, not an error - since "the delegated nameserver
            // isn't somewhere we're willing to connect to" isn't evidence about this zone's
            // configuration either way.
            try {
                SafeAddressValidator.requireSafeIfResolvable(nsIp);
            } catch (java.io.IOException e) {
                continue;
            }
            if (!tcp53Reachable(nsIp)) {
                results.add(new NsCheckResult(ns, false, 0, true, false));
                continue;
            }
            boolean answersAuthoritatively = respondsAuthoritatively(hostname, nsIp);
            if (!includeActiveExploitProbes) {
                results.add(new NsCheckResult(ns, false, 0, answersAuthoritatively, true, false));
                continue;
            }
            AxfrAttempt axfr = attemptAxfr(hostname, nsIp);
            boolean openResolver = isOpenResolver(nsIp);
            results.add(new NsCheckResult(
                    ns, axfr.allowed(), axfr.recordCount(), answersAuthoritatively, true, openResolver));
        }
        return results;
    }

    private List<String> queryNsHostnames(String hostname) {
        List<String> hostnames = new ArrayList<>();
        for (Record record : dns.lookup(hostname, Type.NS).records()) {
            if (record instanceof NSRecord ns) {
                hostnames.add(ns.getTarget().toString(true));
            }
        }
        return hostnames;
    }

    private String resolveA(String hostname) {
        List<Record> records = dns.lookup(hostname, Type.A).records();
        if (records.isEmpty() || !(records.get(0) instanceof ARecord a)) {
            return null;
        }
        return a.getAddress().getHostAddress();
    }

    /**
     * Queries the zone's SOA directly against a specific nameserver's IP (bypassing the public
     * resolver entirely), inspecting the response's actual Rcode rather than going through
     * dnsjava's {@code Lookup} class - see {@code NsTakeoverChecker#respondsAuthoritatively}'s own
     * javadoc for the live false positive this same pattern produced there ({@code Lookup.run()}
     * collapses REFUSED, a timeout, and any other network-level failure into the same
     * {@code null}/"not authoritative" result). An explicit REFUSED is the only outcome treated as
     * lame; a real SOA answer, any other Rcode, or an exception (timeout/network error) all count
     * as "can't confirm lame here" - see DnsZoneDecisionLogic for how this is scored: a single
     * unreachable NS from our vantage point is weaker evidence than the AXFR check's unambiguous
     * "it transferred the zone" signal, so this stays Medium, not Critical, even once accurate.
     */
    private boolean respondsAuthoritatively(String hostname, String nsIp) {
        try {
            SimpleResolver directResolver = new SimpleResolver(nsIp);
            directResolver.setTimeout(TIMEOUT);
            Name name = Name.fromString(hostname, Name.root);
            Record question = Record.newRecord(name, Type.SOA, DClass.IN);
            Message response = directResolver.send(Message.newQuery(question));
            return response.getRcode() != Rcode.REFUSED;
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * A canary name this nameserver has no authority over at all ({@code a.root-servers.net} - one
     * of the most stable A records in all of DNS, chosen so this never breaks from the canary
     * itself changing). A server that is ONLY authoritative for the target's own zone must answer
     * REFUSED/NOTIMP for this; a server that happily recurses and returns a real answer is an open
     * resolver - reachable by anyone on the internet, not just this target's own infrastructure,
     * and a classic DNS-amplification DDoS reflector (RFC 5358). The same direct-to-nameserver
     * connection respondsAuthoritatively already uses, asking a different question.
     */
    private static final Name OPEN_RESOLVER_CANARY_NAME = Name.fromConstantString("a.root-servers.net.");

    private boolean isOpenResolver(String nsIp) {
        try {
            SimpleResolver directResolver = new SimpleResolver(nsIp);
            directResolver.setTimeout(TIMEOUT);
            Record question = Record.newRecord(OPEN_RESOLVER_CANARY_NAME, Type.A, DClass.IN);
            Message query = Message.newQuery(question);
            query.getHeader().setFlag(org.xbill.DNS.Flags.RD);
            Message response = directResolver.send(query);
            return response.getRcode() == Rcode.NOERROR && !response.getSection(org.xbill.DNS.Section.ANSWER).isEmpty();
        } catch (Exception e) {
            return false; // can't confirm open recursion here - not evidence of anything, same as any other probe failure in this class
        }
    }

    private record AxfrAttempt(boolean allowed, int recordCount) {}

    /** A plain TCP connect: AXFR is TCP-only, so a nameserver that won't take a TCP/53 connection can't be assessed here at all. */
    private boolean tcp53Reachable(String nsIp) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(nsIp, 53), (int) TIMEOUT.toMillis());
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * A security review found this had no cap on record count/bytes at all - dnsjava's default
     * (handler-less) {@code run()} buffers every transferred record into one in-memory list with
     * no limit, and the only real bound was a 6-second idle timeout, which a nameserver streaming
     * fast enough (a misconfigured server on a large zone, reachable via a target's own
     * attacker-influenceable NS delegation - this is by definition an external, untrusted server)
     * could avoid ever hitting while still exhausting the shared worker JVM's heap. Caps the
     * transfer itself via a {@link ZoneTransferIn.ZoneTransferHandler}, not just a post-hoc
     * truncation of an already-fully-buffered list, the same "stop the read itself, don't just
     * discard after" reasoning {@link org.freedonia.bloodhound.common.net.SafeHttpGet#readCappedUtf8}
     * already applies to HTTP bodies.
     */
    static final int MAX_AXFR_RECORDS = 50_000;

    /**
     * A rules-parity review found the record-count cap above assumes every record is small -
     * 50,000 records of unbounded SIZE EACH (a handful of maliciously oversized TXT/RRSIG
     * records, say) can still exhaust significant memory well before hitting that count. This is
     * the backstop: wire-format byte count (what actually occupies memory/network, not the
     * record count), summed as records arrive, same "stop the read itself" shape as the count
     * cap right above it. 10MB is generous for any zone this check has a legitimate reason to
     * fully buffer (confirming zone-transfer is allowed, not archiving the zone), while still
     * bounding a hostile nameserver well below anything that threatens the worker's 2G cgroup
     * limit even across several concurrent scans.
     */
    static final int MAX_AXFR_BYTES = 10_000_000;

    /**
     * Unchecked so it can propagate straight out of {@link ZoneTransferIn.ZoneTransferHandler#handleRecord}
     * (which only declares the checked {@link ZoneTransferException}) past dnsjava's internal
     * transfer loop to {@link #attemptAxfr}'s own catch below, without dnsjava mistaking it for a
     * normal protocol-level abort. Deliberately distinct from every other failure path: hitting
     * the cap means AXFR genuinely succeeded (records were flowing) right up until this code chose
     * to stop it - that must still report {@code allowed=true}. Silently falling into the same
     * catch-all as a real refusal would turn a positive "yes, this nameserver allows zone
     * transfers" finding into a false negative purely because the zone happened to be large -
     * exactly backwards for a security check.
     */
    static final class AxfrRecordCapExceeded extends RuntimeException {}

    static final class CappedAxfrHandler implements ZoneTransferIn.ZoneTransferHandler {
        final List<Record> records = new ArrayList<>();
        private long totalBytes = 0;

        @Override
        public void startAXFR() {}

        @Override
        public void startIXFR() {}

        @Override
        public void startIXFRDeletes(Record soa) {}

        @Override
        public void startIXFRAdds(Record soa) {}

        @Override
        public void handleRecord(Record record) {
            if (records.size() >= MAX_AXFR_RECORDS) {
                throw new AxfrRecordCapExceeded();
            }
            totalBytes += record.toWire(Section.ANSWER).length;
            if (totalBytes > MAX_AXFR_BYTES) {
                throw new AxfrRecordCapExceeded();
            }
            records.add(record);
        }
    }

    private AxfrAttempt attemptAxfr(String hostname, String nsIp) {
        CappedAxfrHandler handler = new CappedAxfrHandler();
        try {
            ZoneTransferIn xfr = ZoneTransferIn.newAXFR(Name.fromString(hostname, Name.root), nsIp, null);
            // Duration overload, not the int-seconds one (deprecated in dnsjava 3.6.1) - found
            // while already touching this method for the AXFR record cap below.
            xfr.setTimeout(TIMEOUT);
            xfr.run(handler);
            // A well-behaved refusal throws (ZoneTransferException) rather than returning here, but
            // guard against an empty-but-successful transfer being misread as a positive too.
            return new AxfrAttempt(!handler.records.isEmpty(), handler.records.size());
        } catch (AxfrRecordCapExceeded e) {
            // See the class's own javadoc: capped mid-transfer is still a real "yes" finding, not
            // a refusal - the nameserver was actively streaming zone data when we chose to stop.
            return new AxfrAttempt(true, handler.records.size());
        } catch (Exception e) {
            // The expected, correct outcome for a properly-configured nameserver: refused/reset/timeout.
            return new AxfrAttempt(false, 0);
        }
    }
}
