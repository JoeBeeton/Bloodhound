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
        Long soaSerial) {}
