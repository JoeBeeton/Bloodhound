package org.freedonia.bloodhound.worker.modules.dns;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of already-fetched DNS records into findings - no network calls, fully unit-testable. */
public final class DnsPostureParser {

    private DnsPostureParser() {}

    public static List<RawFinding> parse(String hostname, DnsRecords records) {
        List<RawFinding> findings = new ArrayList<>();
        String dmarcHost = "_dmarc." + hostname;

        Optional<String> spf =
                records.txtRecords().stream().filter(t -> t.toLowerCase().startsWith("v=spf1")).findFirst();
        if (spf.isEmpty()) {
            findings.add(finding("DNS_SPF_MISSING", Severity.HIGH, hostname, Map.of()));
        } else {
            String v = spf.get().toLowerCase();
            if (v.endsWith("+all") || v.endsWith("?all")) {
                findings.add(finding("DNS_SPF_TOO_PERMISSIVE", Severity.MEDIUM, hostname, Map.of("record", spf.get())));
            }
        }

        Optional<String> dmarc = records.dmarcTxtRecords().stream()
                .filter(t -> t.toLowerCase().startsWith("v=dmarc1"))
                .findFirst();
        if (dmarc.isEmpty()) {
            findings.add(finding("DNS_DMARC_MISSING", Severity.HIGH, dmarcHost, Map.of()));
        } else if (dmarc.get().toLowerCase().contains("p=none")) {
            findings.add(finding("DNS_DMARC_POLICY_NONE", Severity.MEDIUM, dmarcHost, Map.of("record", dmarc.get())));
        }

        if (!records.caaPresent()) {
            findings.add(finding("DNS_CAA_MISSING", Severity.LOW, hostname, Map.of()));
        }

        if (!records.dnskeyPresent()) {
            // Presence-only: full DNSSEC chain validation (RRSIG/DS matching
            // up the delegation chain) is out of scope for Phase 1.
            findings.add(finding("DNSSEC_NOT_ENABLED", Severity.MEDIUM, hostname, Map.of()));
        }

        if (!records.mtaStsTxtPresent() || !records.mtaStsPolicyFilePresent()) {
            findings.add(finding("EMAIL_MTA_STS_MISSING", Severity.MEDIUM, hostname, Map.of(
                    "txtPresent", records.mtaStsTxtPresent(), "policyFilePresent", records.mtaStsPolicyFilePresent())));
        }

        if (!records.tlsRptTxtPresent()) {
            findings.add(finding("EMAIL_TLS_RPT_MISSING", Severity.LOW, hostname, Map.of()));
        }

        if (!records.bimiTxtPresent()) {
            // Positive/maturity signal, not a vulnerability - same framing as
            // EXPOSURE_SECURITY_TXT_PRESENT's absence-isn't-penalized stance,
            // except here the record itself would be the good news, so it's
            // the *absence* that's Info-level context, not a real gap.
            findings.add(finding("EMAIL_BIMI_ABSENT", Severity.INFO, hostname, Map.of()));
        }

        if (records.dkimSelectorsFound().isEmpty()) {
            // Best-effort only: a real DKIM setup using a selector name
            // outside the common-name probe list would produce a false
            // "not detected" here, same caveat every ASM tool has for this
            // check - kept at LOW severity to reflect that low confidence.
            findings.add(finding("DNS_DKIM_NOT_DETECTED", Severity.LOW, hostname, Map.of()));
        }

        if (records.wildcardDnsDetected()) {
            // Emitted from here (not SubdomainEnumModule) since it's a
            // single apex-level DNS probe with no per-subdomain fan-out
            // needed - but it's a subdomain-enumeration-confidence signal,
            // hence the SUBDOMAIN_HYGIENE category rather than DNS.
            findings.add(new RawFinding(
                    "SUBDOMAIN_WILDCARD_DNS",
                    Severity.INFO,
                    Category.SUBDOMAIN_HYGIENE,
                    "Wildcard DNS detected",
                    "This zone resolves arbitrary, non-existent subdomains, which means passive subdomain "
                            + "enumeration results for this target may include false positives and should be "
                            + "interpreted with that in mind.",
                    hostname,
                    Map.of()));
        }

        return findings;
    }

    private static RawFinding finding(String ruleId, Severity severity, String asset, Map<String, Object> evidence) {
        String[] copy = COPY.get(ruleId);
        return new RawFinding(ruleId, severity, Category.DNS, copy[0], copy[1], asset, evidence);
    }

    private static final Map<String, String[]> COPY = Map.ofEntries(
            Map.entry(
                    "DNS_SPF_MISSING",
                    new String[] {
                        "Missing SPF record",
                        "No Sender Policy Framework record was found, allowing any server to send email appearing to originate from this domain."
                    }),
            Map.entry(
                    "DNS_SPF_TOO_PERMISSIVE",
                    new String[] {
                        "Overly permissive SPF record",
                        "The SPF record ends in +all or ?all, which allows any server (or fails open) to send mail as this domain."
                    }),
            Map.entry(
                    "DNS_DMARC_MISSING",
                    new String[] {
                        "Missing DMARC record",
                        "No DMARC record was found at _dmarc.<domain>, so spoofed mail claiming to be from this domain is not policed."
                    }),
            Map.entry(
                    "DNS_DMARC_POLICY_NONE",
                    new String[] {
                        "DMARC policy set to none",
                        "A DMARC record exists but its policy is p=none, meaning failing messages are only monitored, not rejected or quarantined."
                    }),
            Map.entry(
                    "DNS_CAA_MISSING",
                    new String[] {
                        "Missing CAA record",
                        "No CAA record restricts which Certificate Authorities may issue certificates for this domain."
                    }),
            Map.entry(
                    "DNSSEC_NOT_ENABLED",
                    new String[] {
                        "DNSSEC not enabled",
                        "No DNSKEY records were found for this zone, indicating the zone is not signed with DNSSEC."
                    }),
            Map.entry(
                    "EMAIL_MTA_STS_MISSING",
                    new String[] {
                        "MTA-STS not fully enforced",
                        "Either the _mta-sts DNS TXT record or the https://mta-sts.<domain>/.well-known/mta-sts.txt "
                                + "policy file is missing, so inbound mail servers have no way to enforce TLS when "
                                + "delivering mail to this domain."
                    }),
            Map.entry(
                    "EMAIL_TLS_RPT_MISSING",
                    new String[] {
                        "TLS-RPT not configured",
                        "No _smtp._tls TXT record was found, so this domain receives no reports when other mail "
                                + "servers fail to negotiate TLS while delivering mail to it."
                    }),
            Map.entry(
                    "EMAIL_BIMI_ABSENT",
                    new String[] {
                        "No BIMI record published",
                        "No default._bimi TXT record was found. BIMI lets supporting mail clients display a "
                                + "verified brand logo next to authenticated mail from this domain - its absence is "
                                + "a maturity signal, not a vulnerability."
                    }),
            Map.entry(
                    "DNS_DKIM_NOT_DETECTED",
                    new String[] {
                        "No DKIM record found at common selector names",
                        "No DKIM TXT record was found at any commonly-used selector name (default, google, "
                                + "selector1, selector2, k1, dkim). DKIM selector names are arbitrary, so this is a "
                                + "best-effort check - a real DKIM setup using an uncommon selector would not be "
                                + "detected by this probe."
                    }));
}
