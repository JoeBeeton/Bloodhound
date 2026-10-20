package org.freedonia.bloodhound.worker.modules.dns;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of already-fetched DNS records into findings - no network calls, fully unit-testable. */
public final class DnsPostureParser {

    private static final int SPF_MAX_LOOKUPS = 10;

    private DnsPostureParser() {}

    public static List<RawFinding> parse(String hostname, DnsRecords records) {
        List<RawFinding> findings = new ArrayList<>();
        String dmarcHost = "_dmarc." + hostname;

        List<String> spfRecords =
                records.txtRecords().stream().filter(t -> t.toLowerCase().startsWith("v=spf1")).toList();
        if (spfRecords.isEmpty()) {
            findings.add(finding("DNS_SPF_MISSING", Severity.HIGH, hostname, Map.of()));
        } else {
            // RFC 7208 4.5: more than one SPF-type TXT record makes the domain's SPF evaluate to
            // PermError regardless of what either record says - "broken", not merely "weak",
            // independent of and worth reporting alongside the permissiveness check below (which
            // still runs against the first record, since that's what most implementations
            // actually read before failing).
            if (spfRecords.size() > 1) {
                findings.add(finding(
                        "DNS_SPF_MULTIPLE_RECORDS", Severity.HIGH, hostname, Map.of("records", spfRecords)));
            }
            String v = spfRecords.get(0).toLowerCase();
            if (v.endsWith("+all") || v.endsWith("?all")) {
                findings.add(finding(
                        "DNS_SPF_TOO_PERMISSIVE", Severity.MEDIUM, hostname, Map.of("record", spfRecords.get(0))));
            }
            // RFC 7208 4.6.4: more than 10 total include/a/mx/ptr/exists/redirect "lookup"
            // mechanisms across the full recursive chain is a hard PermError - the single most
            // common real-world SPF misconfiguration (chaining several third-party ESP/CRM
            // includes adds up fast), and one a human reading just the top-level record would
            // never notice without actually counting through every nested include.
            if (records.spfLookupCount() != null && records.spfLookupCount() > SPF_MAX_LOOKUPS) {
                findings.add(finding(
                        "DNS_SPF_LOOKUP_LIMIT_EXCEEDED",
                        Severity.HIGH,
                        hostname,
                        Map.of("lookupCount", records.spfLookupCount(), "limit", SPF_MAX_LOOKUPS)));
            }
            if (records.spfUsesPtrMechanism()) {
                // RFC 7208 5.5: "SHOULD NOT be used" - slow (a full reverse-then-forward DNS
                // round trip per sender IP), unreliable, and some validators skip evaluating it
                // entirely or treat its mere presence as an automatic fail, independent of the
                // lookup-count limit DNS_SPF_LOOKUP_LIMIT_EXCEEDED already covers.
                findings.add(finding("DNS_SPF_PTR_MECHANISM_DEPRECATED", Severity.LOW, hostname, Map.of()));
            }
        }

        for (String danglingInclude : records.danglingSpfIncludes()) {
            findings.add(finding(
                    "DNS_SPF_INCLUDE_DANGLING",
                    Severity.HIGH,
                    danglingInclude,
                    Map.of("includeDomain", danglingInclude)));
        }

        Optional<String> dmarc = records.dmarcTxtRecords().stream()
                .filter(t -> t.toLowerCase().startsWith("v=dmarc1"))
                .findFirst();
        if (dmarc.isEmpty()) {
            findings.add(finding("DNS_DMARC_MISSING", Severity.HIGH, dmarcHost, Map.of()));
        } else {
            String v = dmarc.get().toLowerCase();
            // Independent of the p=none check below - a record can have p=reject and still have
            // nobody watching aggregate reports, or p=none with reports configured. Both gaps
            // matter on their own.
            if (v.contains("p=none")) {
                findings.add(finding("DNS_DMARC_POLICY_NONE", Severity.MEDIUM, dmarcHost, Map.of("record", dmarc.get())));
            }
            if (!v.contains("rua=")) {
                findings.add(finding("EMAIL_DMARC_RUA_MISSING", Severity.LOW, dmarcHost, Map.of("record", dmarc.get())));
            }
            // pct= defaults to 100 per RFC 7489 5.3 when absent - only a record that explicitly
            // sets it below 100 is a real gap (enforcement applies to just a sampled fraction of
            // mail), never its mere absence.
            Integer pct = parsePct(v);
            if (pct != null && pct < 100) {
                findings.add(finding(
                        "EMAIL_DMARC_PCT_BELOW_100", Severity.LOW, dmarcHost,
                        Map.of("record", dmarc.get(), "pct", pct)));
            }
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
        findings.addAll(dkimWeakKeyFindings(hostname, records));

        for (String danglingHost : records.danglingMxHosts()) {
            findings.add(finding(
                    "DNS_MX_TO_DANGLING_HOST",
                    Severity.HIGH,
                    danglingHost,
                    Map.of("mxHost", danglingHost)));
        }

        if (records.soaSerial() != null) {
            LocalDate encoded = tryParseSoaSerialAsDate(records.soaSerial());
            if (encoded != null) {
                long yearsOld = ChronoUnit.YEARS.between(encoded, LocalDate.now(ZoneOffset.UTC));
                if (yearsOld >= 2) {
                    findings.add(finding(
                            "DNS_SOA_SERIAL_STALE",
                            Severity.LOW,
                            hostname,
                            Map.of("serial", records.soaSerial(), "encodedDate", encoded.toString())));
                }
            }
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

    private static final Pattern PCT_PATTERN = Pattern.compile("pct=(\\d{1,3})");

    private static Integer parsePct(String dmarcRecordLowercase) {
        Matcher m = PCT_PATTERN.matcher(dmarcRecordLowercase);
        return m.find() ? Integer.parseInt(m.group(1)) : null;
    }

    /**
     * Interprets a SOA serial under the near-universal YYYYMMDDnn convention (the two trailing
     * digits are a same-day revision counter) - not every zone actually follows it (a plain
     * incrementing integer is equally valid per RFC 1035), so this only returns a date when the
     * serial is exactly 10 digits AND those digits form a real calendar date within a sane range
     * (1990 through the current year) - anything else (a 5-digit incrementing counter, a
     * randomly-seeded value, a future-dated typo) is "can't tell", not "must be very old",
     * matching this file's own DNS_DKIM_NOT_DETECTED precedent for a best-effort, low-confidence
     * signal: LOW severity, and silence rather than a guess when the convention doesn't hold.
     */
    static LocalDate tryParseSoaSerialAsDate(long serial) {
        if (serial < 1_000_000_000L || serial > 9_999_999_999L) {
            return null;
        }
        String digits = Long.toString(serial);
        try {
            int year = Integer.parseInt(digits.substring(0, 4));
            int month = Integer.parseInt(digits.substring(4, 6));
            int day = Integer.parseInt(digits.substring(6, 8));
            if (year < 1990 || year > LocalDate.now(ZoneOffset.UTC).getYear()) {
                return null;
            }
            return LocalDate.of(year, month, day);
        } catch (Exception e) {
            return null;
        }
    }

    /** Threshold per current DKIM best-practice guidance (M3AAWG, dkim.org) - RSA keys below this are considered crackable with realistic resources, the same line NIST drew for RSA generally back in 2013. */
    private static final int MIN_DKIM_RSA_KEY_BITS = 2048;

    /**
     * Only evaluates selectors this module's own best-effort probe already found (see
     * DNS_DKIM_NOT_DETECTED above) - a selector using an uncommon name is invisible to this check
     * for the exact same reason. Each selector is judged independently: a domain can have one
     * strong and one weak key live at once (e.g. mid-rotation).
     */
    static List<RawFinding> dkimWeakKeyFindings(String hostname, DnsRecords records) {
        List<RawFinding> findings = new ArrayList<>();
        List<String> selectors = records.dkimSelectorsFound();
        List<String> rawTxt = records.dkimRawTxtFound();
        for (int i = 0; i < selectors.size() && i < rawTxt.size(); i++) {
            String selector = selectors.get(i);
            DkimKeyAnalyzer.rsaKeyBitLength(rawTxt.get(i)).filter(bits -> bits < MIN_DKIM_RSA_KEY_BITS).ifPresent(bits -> {
                String asset = selector + "._domainkey." + hostname;
                findings.add(finding(
                        "DNS_DKIM_WEAK_KEY", Severity.MEDIUM, asset, Map.of("selector", selector, "keyBits", bits)));
            });
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
                    "EMAIL_DMARC_RUA_MISSING",
                    new String[] {
                        "DMARC record has no aggregate report address",
                        "A DMARC record exists but has no rua= tag, so nobody receives aggregate reports of "
                                + "authentication failures - even a strict p=reject policy is running with no "
                                + "visibility into what's actually being blocked or who's sending unauthenticated "
                                + "mail as this domain."
                    }),
            Map.entry(
                    "DNS_MX_TO_DANGLING_HOST",
                    new String[] {
                        "MX record points to a non-resolving host",
                        "This domain's MX record points to a mail server hostname that no longer resolves (no A "
                                + "or AAAA record) - the same takeover shape as a dangling CNAME, applied to mail "
                                + "routing: anyone able to register or re-point that abandoned hostname could "
                                + "intercept mail addressed to this domain."
                    }),
            Map.entry(
                    "DNS_SPF_MULTIPLE_RECORDS",
                    new String[] {
                        "Multiple SPF records published",
                        "More than one SPF-type TXT record was found at this domain's apex. Per RFC 7208, this "
                                + "makes SPF evaluation return PermError regardless of what either record says - "
                                + "mail servers checking SPF for this domain get a hard failure, not the weaker of "
                                + "the two policies."
                    }),
            Map.entry(
                    "DNS_SPF_LOOKUP_LIMIT_EXCEEDED",
                    new String[] {
                        "SPF record exceeds the 10-lookup limit",
                        "This domain's SPF record requires more than 10 DNS \"lookup\" mechanisms "
                                + "(include/a/mx/ptr/exists/redirect) once every nested include is followed - RFC "
                                + "7208 mandates a hard PermError past this limit, meaning most mail servers "
                                + "checking SPF for this domain treat it as if SPF were entirely broken, "
                                + "regardless of how carefully the policy itself was written."
                    }),
            Map.entry(
                    "DNS_SPF_INCLUDE_DANGLING",
                    new String[] {
                        "SPF record includes a domain with no SPF record of its own",
                        "This domain's SPF record references another domain via include: that has no SPF TXT "
                                + "record of its own - the same takeover shape as a dangling CNAME or MX, applied to "
                                + "SPF: whoever can register or reconfigure that referenced domain could add "
                                + "themselves as an authorized sender for this domain's mail."
                    }),
            Map.entry(
                    "EMAIL_DMARC_PCT_BELOW_100",
                    new String[] {
                        "DMARC policy applies to only a fraction of mail",
                        "The DMARC record's pct= value is below 100, so its policy (quarantine/reject) is only "
                                + "enforced for a sampled percentage of messages that fail authentication - the rest "
                                + "are treated as if the policy were p=none, regardless of how strict the policy "
                                + "itself looks."
                    }),
            Map.entry(
                    "DNS_SOA_SERIAL_STALE",
                    new String[] {
                        "SOA serial suggests an unmaintained zone",
                        "This zone's SOA serial number, read under the common YYYYMMDDnn convention, encodes a "
                                + "date more than 2 years in the past - a signal (not proof, since not every zone "
                                + "uses this convention) that the zone's DNS records haven't been updated in a long "
                                + "time and may reflect abandoned or unmaintained infrastructure."
                    }),
            Map.entry(
                    "DNS_DKIM_NOT_DETECTED",
                    new String[] {
                        "No DKIM record found at common selector names",
                        "No DKIM TXT record was found at any commonly-used selector name (default, google, "
                                + "selector1, selector2, k1, dkim). DKIM selector names are arbitrary, so this is a "
                                + "best-effort check - a real DKIM setup using an uncommon selector would not be "
                                + "detected by this probe."
                    }),
            Map.entry(
                    "DNS_SPF_PTR_MECHANISM_DEPRECATED",
                    new String[] {
                        "SPF record uses the deprecated ptr mechanism",
                        "This domain's SPF record uses the ptr (or ptr:domain) mechanism, which RFC 7208 5.5 "
                                + "explicitly says SHOULD NOT be used: it requires a slow reverse-then-forward DNS "
                                + "lookup per sender IP, is unreliable, and some mail validators skip evaluating it "
                                + "entirely or treat its mere presence as an automatic SPF failure."
                    }),
            Map.entry(
                    "DNS_DKIM_WEAK_KEY",
                    new String[] {
                        "DKIM record uses a weak RSA key",
                        "A DKIM TXT record was found with an RSA public key below 2048 bits - the current minimum "
                                + "recommended by DKIM deployment guidance (M3AAWG, dkim.org), matching the same line "
                                + "NIST drew for RSA generally in 2013. A key this size is within reach of realistic "
                                + "factoring resources, letting an attacker forge DKIM-valid mail from this domain."
                    }));
}
