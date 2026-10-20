package org.freedonia.bloodhound.worker.modules.dns;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.worker.modules.common.FallbackDnsLookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * Fetch side of the DNS posture check: raw record queries only, no
 * interpretation - see DnsPostureParser for that. Uses dnsjava rather than
 * raw JNDI DNS contexts (simpler API, no native deps).
 *
 * <p>Queries go to a public recursive resolver over TCP first, falling back to
 * the platform resolver - see {@link FallbackDnsLookup} for why both halves
 * matter. TCP because a real target's apex TXT set (github.com: SPF plus
 * many site-verification records) can exceed what a UDP answer carries.
 *
 * <p>{@link #fetch} refuses to run when DNS itself is unreachable: every
 * rule DnsPostureParser derives from this data is an absence check, so an
 * empty answer set caused by a dead resolver would - and, before this guard,
 * did - fire every one of them at once on domains that publish all of it.
 * Failing the job is honest; a sheet of false "missing" findings is not.
 */
public class DnsRecordFetcher {

    /**
     * Common DKIM selector names, per every ASM/security-scanner's shared
     * caveat: the real selector is chosen by whoever configured the mail
     * system and isn't discoverable generically, so this is inherently a
     * best-effort probe of the handful of names actually seen in practice
     * (Google Workspace's "google", Mailchimp/generic "k1", and the plain
     * "default"/"selector1"/"selector2" convention several ESPs default to).
     */
    private static final List<String> COMMON_DKIM_SELECTORS =
            List.of("default", "google", "selector1", "selector2", "k1", "dkim");

    private final FallbackDnsLookup dns = new FallbackDnsLookup(true);
    private final HttpClient httpClient;

    public DnsRecordFetcher() {
        this.httpClient =
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    public DnsRecords fetch(String hostname) throws ScanModuleException {
        // Canary: an NS query for the target. Any answer at all (records, NXDOMAIN, NODATA) proves
        // a resolver is reachable; only a resolver-level failure on both paths fails the job.
        if (!dns.lookup(hostname, Type.NS).answered()) {
            throw new ScanModuleException(
                    "DNS resolvers unreachable - cannot assess DNS posture for " + hostname
                            + " (refusing to report every record as missing)");
        }
        List<String> txt = queryTxt(hostname);
        List<String> dmarcTxt = queryTxt("_dmarc." + hostname);
        boolean caaPresent = !queryRecords(hostname, Type.CAA).isEmpty();
        boolean dnskeyPresent = !queryRecords(hostname, Type.DNSKEY).isEmpty();

        boolean mtaStsTxt = queryTxt("_mta-sts." + hostname).stream()
                .anyMatch(t -> t.toLowerCase().startsWith("v=stsv1"));
        boolean mtaStsPolicy = fetchesOk("https://mta-sts." + hostname + "/.well-known/mta-sts.txt");
        boolean tlsRpt = queryTxt("_smtp._tls." + hostname).stream()
                .anyMatch(t -> t.toLowerCase().startsWith("v=tlsrptv1"));
        boolean bimi = queryTxt("default._bimi." + hostname).stream()
                .anyMatch(t -> t.toLowerCase().startsWith("v=bimi1"));

        List<String> dkimSelectorsFound = new ArrayList<>();
        List<String> dkimRawTxtFound = new ArrayList<>();
        for (String selector : COMMON_DKIM_SELECTORS) {
            List<String> selectorTxt = queryTxt(selector + "._domainkey." + hostname);
            if (!selectorTxt.isEmpty()) {
                dkimSelectorsFound.add(selector);
                dkimRawTxtFound.add(selectorTxt.get(0));
            }
        }

        boolean wildcard = probeWildcard(hostname);
        List<String> danglingMx = findDanglingMxHosts(hostname);
        List<String> danglingSpfIncludes = findDanglingSpfIncludes(txt);
        SoaTiming soaTiming = querySoaRecord(hostname);
        Long soaSerial = soaTiming == null ? null : soaTiming.serial();
        boolean hasTopLevelSpf = txt.stream().anyMatch(t -> t.toLowerCase(java.util.Locale.ROOT).startsWith("v=spf1"));
        SpfWalkResult spfWalk =
                hasTopLevelSpf ? walkSpf(hostname, new java.util.HashSet<>(), 0) : new SpfWalkResult(0, false);
        Integer spfLookupCount = hasTopLevelSpf ? spfWalk.lookupCount() : null;

        return new DnsRecords(
                txt, dmarcTxt, caaPresent, dnskeyPresent, mtaStsTxt, mtaStsPolicy, tlsRpt, bimi, dkimSelectorsFound,
                wildcard, danglingMx, danglingSpfIncludes, soaSerial, spfLookupCount, dkimRawTxtFound,
                spfWalk.usesPtrMechanism(), soaTiming == null ? null : soaTiming.refreshSeconds(),
                soaTiming == null ? null : soaTiming.retrySeconds());
    }

    /** Defensive recursion cap for a malicious/circular include chain - RFC 7208's own limit is 10 total lookups, so a legitimate chain never approaches this depth; it exists purely to guarantee termination. */
    private static final int MAX_SPF_RECURSION_DEPTH = 10;

    /** Total RFC 7208 4.6.4 "lookup" mechanisms across the full chain, and whether any of them was the deprecated ptr mechanism (RFC 7208 5.5: "SHOULD NOT be used" - slow, unreliable, and some validators treat its mere presence as an automatic fail). */
    private record SpfWalkResult(int lookupCount, boolean usesPtrMechanism) {
        static SpfWalkResult combine(SpfWalkResult a, SpfWalkResult b) {
            return new SpfWalkResult(a.lookupCount() + b.lookupCount(), a.usesPtrMechanism() || b.usesPtrMechanism());
        }
    }

    /**
     * Counts every RFC 7208 4.6.4 "lookup" mechanism (include/a/mx/ptr/exists/redirect - ip4/ip6/
     * all/exp don't count) across the full recursive SPF evaluation chain, following include:/
     * redirect= into the referenced domain's own SPF record and continuing the count there - the
     * single most common real-world SPF misconfiguration this product had no check for at all:
     * RFC 7208 mandates a hard PermError once the total exceeds 10, silently breaking SPF
     * validation for every mail server that enforces the limit (most modern ones do), even though
     * the top-level record "looks" fine to a human reading just it in isolation. A circular or
     * too-deep chain (visited-set/depth guard) stops counting further rather than looping forever -
     * already broken in a different way at that point, not this check's job to diagnose. Also
     * tracks ptr-mechanism usage anywhere in the chain along the way, since the walk already visits
     * every term - DNS_SPF_PTR_MECHANISM_DEPRECATED's own input.
     */
    private SpfWalkResult walkSpf(String domain, java.util.Set<String> visited, int depth) {
        if (depth >= MAX_SPF_RECURSION_DEPTH || !visited.add(domain.toLowerCase(java.util.Locale.ROOT))) {
            return new SpfWalkResult(0, false);
        }
        return queryTxt(domain).stream()
                .filter(t -> t.toLowerCase(java.util.Locale.ROOT).startsWith("v=spf1"))
                .findFirst()
                .map(record -> walkMechanisms(record, visited, depth))
                .orElse(new SpfWalkResult(0, false));
    }

    private SpfWalkResult walkMechanisms(String spfRecord, java.util.Set<String> visited, int depth) {
        SpfWalkResult result = new SpfWalkResult(0, false);
        for (String term : spfRecord.split("\\s+")) {
            String lower = term.toLowerCase(java.util.Locale.ROOT);
            if (lower.startsWith("include:")) {
                result = SpfWalkResult.combine(result, SpfWalkResult.combine(
                        new SpfWalkResult(1, false), walkSpf(term.substring("include:".length()), visited, depth + 1)));
            } else if (lower.startsWith("redirect=")) {
                result = SpfWalkResult.combine(result, SpfWalkResult.combine(
                        new SpfWalkResult(1, false),
                        walkSpf(term.substring("redirect=".length()), visited, depth + 1)));
            } else if (lower.equals("a") || lower.startsWith("a:") || lower.startsWith("a/")) {
                result = SpfWalkResult.combine(result, new SpfWalkResult(1, false));
            } else if (lower.equals("mx") || lower.startsWith("mx:") || lower.startsWith("mx/")) {
                result = SpfWalkResult.combine(result, new SpfWalkResult(1, false));
            } else if (lower.equals("ptr") || lower.startsWith("ptr:")) {
                result = SpfWalkResult.combine(result, new SpfWalkResult(1, true));
            } else if (lower.startsWith("exists:")) {
                result = SpfWalkResult.combine(result, new SpfWalkResult(1, false));
            }
        }
        return result;
    }

    private static final Pattern SPF_INCLUDE_PATTERN = Pattern.compile("include:([^\\s]+)", Pattern.CASE_INSENSITIVE);

    /**
     * Top-level {@code include:} mechanisms (nested includes-of-includes aren't followed - same
     * best-effort scope this file's DKIM selector probing already accepts) whose referenced
     * domain has no SPF TXT record of its own at all. The same takeover shape as a dangling MX
     * or CNAME: an SPF include only works because the referenced domain publishes SPF for it to
     * inherit - if nobody's there to answer, whoever registers that domain (if it's not even
     * registered at all) can add their own permissive SPF record and become an authorized
     * sender for this domain's mail.
     */
    private List<String> findDanglingSpfIncludes(List<String> txtRecords) {
        List<String> dangling = new ArrayList<>();
        for (String record : txtRecords) {
            if (!record.toLowerCase().startsWith("v=spf1")) {
                continue;
            }
            Matcher matcher = SPF_INCLUDE_PATTERN.matcher(record);
            while (matcher.find()) {
                String includeDomain = matcher.group(1);
                boolean hasSpf =
                        queryTxt(includeDomain).stream().anyMatch(t -> t.toLowerCase().startsWith("v=spf1"));
                if (!hasSpf && !dangling.contains(includeDomain)) {
                    dangling.add(includeDomain);
                }
            }
        }
        return dangling;
    }

    /** One SOA record's serial/refresh/retry, in seconds for the latter two - null if the apex has no SOA (shouldn't normally happen for a zone that answered the earlier NS canary, but DNS is DNS). See DnsPostureParser for how each is interpreted. */
    private record SoaTiming(long serial, long refreshSeconds, long retrySeconds) {}

    private SoaTiming querySoaRecord(String hostname) {
        for (Record record : queryRecords(hostname, Type.SOA)) {
            if (record instanceof SOARecord soa) {
                return new SoaTiming(soa.getSerial(), soa.getRefresh(), soa.getRetry());
            }
        }
        return null;
    }

    /**
     * MX targets that don't resolve at all (no A, no AAAA) - the same takeover shape
     * SUBDOMAIN_DANGLING_CNAME already covers for CNAMEs, applied to mail routing instead: a
     * dangling MX still means "this domain accepts mail routed to a host nobody controls
     * anymore," which anyone able to register or re-point that dangling name can intercept.
     */
    private List<String> findDanglingMxHosts(String hostname) {
        List<String> dangling = new ArrayList<>();
        for (Record record : queryRecords(hostname, Type.MX)) {
            if (!(record instanceof MXRecord mx)) {
                continue;
            }
            String target = mx.getTarget().toString(true);
            boolean resolves = !queryRecords(target, Type.A).isEmpty() || !queryRecords(target, Type.AAAA).isEmpty();
            if (!resolves) {
                dangling.add(target);
            }
        }
        return dangling;
    }

    /** A definitely-nonexistent name resolving at all means the zone has wildcard DNS configured on its apex. */
    private boolean probeWildcard(String hostname) {
        String probe = "bh-wildcard-probe-" + UUID.randomUUID().toString().replace("-", "") + "." + hostname;
        return !queryRecords(probe, Type.A).isEmpty();
    }

    /**
     * A security review found this connected via a plain, unguarded HttpClient.send() - the
     * derived hostname ("mta-sts." + the target's apex) is not itself re-checked against
     * SafeAddressValidator the way the apex is at target-creation time, and even if it were, DNS
     * for this specific subdomain is independently attacker-controlled regardless of what the
     * apex resolves to. Without a guard, this was a 443 reachability oracle into RFC1918/
     * link-local space. SafeHttpGet.get() resolves-and-checks the host before connecting, the
     * same guard every other outbound HTTP fetch in this codebase already uses.
     *
     * <p>maxRedirects 0, not some positive bound: RFC 8461 (MTA-STS) requires the policy fetch to
     * NOT follow HTTP redirects at all - a redirected response must be treated as "no valid
     * policy," which SafeHttpGet.get() already does for free here (a 3xx with nowhere left to go
     * throws, caught below and treated the same as any other failed fetch), so this is both the
     * security fix and the spec-correct behavior in one change.
     */
    private boolean fetchesOk(String url) {
        try {
            HttpResponse<Void> response = SafeHttpGet.get(
                    httpClient, url, Duration.ofSeconds(6), ScanUserAgent.VALUE, HttpResponse.BodyHandlers.discarding(), 0);
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> queryTxt(String name) {
        List<String> values = new ArrayList<>();
        for (Record record : queryRecords(name, Type.TXT)) {
            if (record instanceof TXTRecord txt) {
                values.add(String.join("", txt.getStrings()));
            }
        }
        return values;
    }

    /** A lookup that fails on both resolvers after the canary passed is a transient blip, logged by FallbackDnsLookup - treated as empty. */
    private List<Record> queryRecords(String name, int type) {
        return dns.lookup(name, type).records();
    }
}
