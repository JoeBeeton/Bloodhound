package org.freedonia.bloodhound.worker.modules.dns;

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

    public record NsCheckResult(String nameserver, boolean axfrAllowed, int axfrRecordCount, boolean answeredAuthoritatively) {}

    public List<NsCheckResult> fetch(String hostname) {
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
            boolean answersAuthoritatively = respondsAuthoritatively(hostname, nsIp);
            AxfrAttempt axfr = attemptAxfr(hostname, nsIp);
            results.add(new NsCheckResult(ns, axfr.allowed(), axfr.recordCount(), answersAuthoritatively));
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

    private record AxfrAttempt(boolean allowed, int recordCount) {}

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
