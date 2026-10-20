package org.freedonia.bloodhound.worker.modules.dns;

import java.util.List;

/** Raw fetch output for one hostname - no interpretation yet, see DnsPostureParser. */
public record DnsRecords(
        List<String> txtRecords,
        List<String> dmarcTxtRecords,
        boolean caaPresent,
        boolean dnskeyPresent,
        boolean mtaStsTxtPresent,
        boolean mtaStsPolicyFilePresent,
        boolean tlsRptTxtPresent,
        boolean bimiTxtPresent,
        List<String> dkimSelectorsFound,
        boolean wildcardDnsDetected,
        List<String> danglingMxHosts,
        List<String> danglingSpfIncludes,
        Long soaSerial,
        /** Total RFC 7208 4.6.4 "lookup" mechanisms (include/a/mx/ptr/exists/redirect) across the
         * full recursive SPF evaluation chain - null when there's no SPF record to evaluate at all
         * (DNS_SPF_MISSING already covers that case separately). See DnsRecordFetcher#countSpfLookups. */
        Integer spfLookupCount,
        /** Each found selector's own raw TXT value, same order/count as dkimSelectorsFound - the
         * input to DkimKeyAnalyzer's weak-RSA-key check. Kept as a separate parallel list rather
         * than widening dkimSelectorsFound's element type, so every existing call site that only
         * cares about selector names (DNS_DKIM_NOT_DETECTED's own "found anything at all" check)
         * is unaffected. */
        List<String> dkimRawTxtFound,
        /** Whether any mechanism anywhere in the full recursive SPF chain was ptr/ptr: - see
         * DnsRecordFetcher#walkSpf. False (not null) when there's no SPF record at all, same as
         * every other SPF-chain boolean here - DNS_SPF_MISSING already covers that case. */
        boolean spfUsesPtrMechanism) {}
