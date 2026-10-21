package org.freedonia.bloodhound.worker.modules.subdomain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Subdomain discovery via ProjectDiscovery's katana crawler (installed in the worker image; see
 * Dockerfile), specifically its {@code -jc/-js-crawl} mode: rather than a passive lookup like
 * crt.sh/subfinder, this crawls the target's own site and parses every JS file it fetches for
 * endpoint-shaped strings - catching hostnames a company's own frontend code references
 * (internal API hosts, staging endpoints) that never got a public CT-logged cert and aren't a
 * guessable wordlist entry, which is exactly what the other two sources structurally can't see.
 *
 * <p>Verified against katana v1.7.0's real output shape by crawling a live authorized target
 * (jaja.co.uk) and inspecting the raw jsonl: each record's {@code request.tag} says how that URL
 * was found ({@code "js"} = parsed out of a fetched JS/CSS file's content, vs {@code "a"} for a
 * plain HTML link, {@code "script"} for a script tag's own src, etc.) - only {@code "js"} records
 * are kept here, matching this source's specific "search JS files" scope; the broader
 * link-crawling katana also does (which found a real off-catalog host, jaja.jaja.finance, via a
 * plain page link during that same verification run) is a different, separately-worth-having
 * technique, not this one.
 *
 * <p>{@code -fs rdn} keeps katana's own crawl recursion inside the root domain, but it still
 * reports (fetches and emits a record for) plenty of genuinely out-of-scope hosts it links to
 * (fonts.googleapis.com, facebook.com, etc.) without following them further - confirmed live,
 * this is not a scoping bug on katana's side to rely on, so {@link #inScope} does the actual
 * filtering here rather than trusting every reported hostname.
 *
 * <p>{@code -ct 45s} (crawl-duration) is katana's own wall-clock cap, comfortably inside
 * {@link ExternalCliSubdomainSource}'s shared 75s hard-kill watchdog - a real crawl's runtime
 * depends on the target's own size in a way a passive lookup's doesn't, so this needs its own
 * self-imposed budget rather than relying on the shared watchdog's blunter kill (which was
 * confirmed live to still yield whatever partial jsonl had already been read off the pipe by that
 * point - not empty, but no reason to rely on that when katana can bound its own run cleanly).
 * {@code -mdp 500} is a secondary page-count cap for the same reason. {@code -or -ob} (omit raw
 * request/response, omit body) keep the output to just what's needed - full page bodies made a
 * short verification crawl run into megabytes of jsonl for no benefit here.
 */
@Component
public class KatanaCliSource extends ExternalCliSubdomainSource {

    private static final Logger log = LoggerFactory.getLogger(KatanaCliSource.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * A security review found two real gaps here. First: nothing validated {@code rootDomain}
     * itself before exec'ing katana at it - a target's hostname is checked for a private/internal
     * address only at creation time (central-server), and DNS can point somewhere else by the
     * time a scan actually runs (rebinding). {@link #isUnsafeToScan} now closes that one directly,
     * the same {@link SafeAddressValidator} gate every other direct-subprocess/HTTP-fetching
     * module in this codebase already has. Second, and not fully closed by anything below: -fs
     * rdn (see the class doc above) only bounds which hosts katana *recurses into* - it still
     * performs the fetch for an out-of-scope URL it discovers mid-crawl (the class doc's own
     * fonts.googleapis.com/facebook.com example), and the worker container shares app_net with
     * central-server, so that fetch can in principle reach the control plane. {@code -cs} below is
     * katana's own documented "in scope url regex to be followed" mechanism, added as defense in
     * depth - but ProjectDiscovery's docs don't state whether it gates the fetch itself or only
     * what's followed afterward, and this review had no katana binary available to verify that
     * empirically. The actually robust fix is taking this subprocess off app_net entirely; that is
     * a larger infrastructure change, not done here.
     */
    @Override
    protected boolean isUnsafeToScan(String rootDomain) {
        try {
            SafeAddressValidator.requireSafeIfResolvable(rootDomain);
            return false;
        } catch (IOException unsafe) {
            return true;
        }
    }

    @Override
    protected List<String> command(String rootDomain) {
        return List.of(
                "katana",
                "-u", "https://" + rootDomain + "/",
                "-jc",
                "-fs", "rdn",
                "-cs", crawlScopeRegex(rootDomain),
                "-silent",
                "-j",
                "-or",
                "-ob",
                "-timeout", "8",
                "-c", "10",
                "-ct", "45s",
                "-mdp", "500");
    }

    /**
     * Pure and unit-testable on its own, independent of whether katana's {@code -cs} actually
     * gates the fetch (see {@link #isUnsafeToScan}'s doc) - this is katana's own regex dialect
     * (Go RE2), not {@code java.util.regex}, so the domain is hand-escaped rather than via {@code
     * Pattern.quote} (whose {@code \Q...\E} wrapper RE2 does not understand).
     */
    static String crawlScopeRegex(String rootDomain) {
        String escapedDomain = rootDomain.toLowerCase(Locale.ROOT).replace(".", "\\.");
        return "(?i)^https?://([a-z0-9-]+\\.)*" + escapedDomain + "(:[0-9]+)?(/.*)?$";
    }

    @Override
    protected List<String> parseOutput(String stdout, String rootDomain) {
        return parse(stdout, rootDomain);
    }

    /** Pure: one jsonl record per line; keeps only js-content-parsed endpoints within scope. */
    static List<String> parse(String stdout, String rootDomain) {
        if (stdout == null || stdout.isBlank()) {
            return List.of();
        }
        String domain = rootDomain.toLowerCase();
        Set<String> hostnames = new LinkedHashSet<>();
        for (String line : stdout.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            try {
                JsonNode record = MAPPER.readTree(line);
                JsonNode request = record.path("request");
                if (!"js".equals(request.path("tag").asText(""))) {
                    continue;
                }
                String endpoint = request.path("endpoint").asText("");
                String host = URI.create(endpoint).getHost();
                if (host != null && inScope(host.toLowerCase(), domain)) {
                    hostnames.add(host.toLowerCase());
                }
            } catch (Exception malformedOrPartialLine) {
                // A line truncated by the shared watchdog's forced kill, or any endpoint string
                // that isn't a real absolute URI (katana's regex-based js parsing occasionally
                // matches non-URL-shaped strings) - skip it, not worth failing this source over.
            }
        }
        return new ArrayList<>(hostnames);
    }

    private static boolean inScope(String host, String rootDomain) {
        return host.equals(rootDomain) || host.endsWith("." + rootDomain);
    }

    @Override
    public String sourceName() {
        return "KATANA";
    }
}
