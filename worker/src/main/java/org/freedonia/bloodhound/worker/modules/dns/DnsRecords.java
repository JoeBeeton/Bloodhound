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
        Integer spfLookupCount) {}
