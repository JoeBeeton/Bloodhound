package org.freedonia.bloodhound.worker.modules.breach;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

/**
 * Real {@link BreachCorrelationSource} implementation against Have I Been
 * Pwned's domain-search API - the "implement BreachCorrelationSource against
 * a real provider" step {@link BreachCorrelationModule}'s javadoc calls for.
 * {@code @Primary} so Spring injects this instead of
 * {@link NoOpBreachCorrelationSource} into {@link BreachCorrelationModule}
 * (which still gates on {@code HIBP_API_KEY} being set before ever calling
 * this class - see its own javadoc - so an operator without a key gets
 * exactly the same inert behavior as before this existed).
 *
 * <p><b>Requires more than just an API key.</b> HIBP's domain-search
 * endpoint ({@code GET /breacheddomain/{domain}}) only returns data for
 * domains the operator has manually verified ownership of under their own
 * HIBP account (via DNS TXT record, email approval, or their dashboard) -
 * querying an unverified domain returns HTTP 403, every time, regardless of
 * how valid the API key is. That verification is a one-time, per-domain,
 * account-level action only the operator can take (HIBP's own dashboard,
 * outside anything Bloodhound can automate) - this class treats 403 as "no
 * data available" rather than an error (see {@link HibpDecisionLogic}), so
 * an unverified target simply produces zero breach findings rather than
 * failing the scan. <b>Not live-verified against a real HIBP subscription</b>
 * as part of building this - written strictly to the documented API
 * contract (https://haveibeenpwned.com/API/v3), unlike everything else
 * fetch-related in this codebase, which has all been confirmed against
 * live responses. Worth a real end-to-end check against an actual verified
 * domain once a subscription exists.
 *
 * <p>The domain-search response only returns breach *names* per email alias
 * (e.g. {@code {"alias1": ["Adobe"], "alias2": ["Adobe","Gawker"]}} -
 * HIBP never exposes full email addresses back, by design); a second,
 * unauthenticated call per unique breach name ({@code GET /breach/{name}})
 * fills in the description/date {@link BreachCorrelationSource.BreachRecord}
 * needs. Breach details (unlike domain-search results) are the same for
 * every caller and effectively static once published, so they're cached
 * for this worker process's lifetime - a plain in-memory map, not a
 * persistent/cross-worker cache (workers hold no database credentials by
 * design - see the architecture notes elsewhere in this codebase), which
 * still meaningfully cuts redundant calls to a source HIBP's own docs ask
 * to be queried "infrequently".
 */
@Component
@Primary
public class HibpBreachCorrelationSource implements BreachCorrelationSource {

    private final HibpFetcher fetcher;
    private final ConcurrentHashMap<String, Optional<HibpDecisionLogic.BreachDetail>> detailCache =
            new ConcurrentHashMap<>();

    public HibpBreachCorrelationSource(@Value("${bloodhound.worker.hibp-api-key:}") String apiKey) {
        this.fetcher = new HibpFetcher(apiKey);
    }

    @Override
    public List<BreachRecord> lookup(String domain) throws Exception {
        HibpFetcher.RawResponse domainResponse = fetcher.fetchDomainSearch(domain);
        Set<String> breachNames =
                HibpDecisionLogic.parseDomainSearchBreachNames(domainResponse.statusCode(), domainResponse.body());

        List<BreachRecord> records = new ArrayList<>();
        for (String breachName : breachNames) {
            Optional<HibpDecisionLogic.BreachDetail> detail = detailFor(breachName);
            records.add(new BreachRecord(
                    breachName,
                    detail.map(HibpDecisionLogic.BreachDetail::description).orElse(null),
                    detail.map(HibpDecisionLogic.BreachDetail::breachDate).orElse(null)));
        }
        return records;
    }

    private Optional<HibpDecisionLogic.BreachDetail> detailFor(String breachName) throws Exception {
        Optional<HibpDecisionLogic.BreachDetail> cached = detailCache.get(breachName);
        if (cached != null) {
            return cached;
        }
        HibpFetcher.RawResponse response = fetcher.fetchBreachDetail(breachName);
        Optional<HibpDecisionLogic.BreachDetail> detail =
                HibpDecisionLogic.parseBreachDetail(response.statusCode(), response.body());
        detailCache.put(breachName, detail);
        return detail;
    }
}
