package org.freedonia.bloodhound.worker.modules.dns;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class DnsPostureParserTest {

    /** Every check compliant: no findings expected unless a test overrides one field via the copy* helpers. */
    private static DnsRecords compliant() {
        return new DnsRecords(
                List.of("v=spf1 include:_spf.example.com -all"),
                List.of("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
                true,
                true,
                true,
                true,
                true,
                true,
                List.of("default"),
                false,
                List.of());
    }

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    @Test
    void allPresentAndStrict_producesNoFindings() {
        assertThat(DnsPostureParser.parse("example.com", compliant())).isEmpty();
    }

    @Test
    void missingSpf_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_SPF_MISSING");
    }

    @Test
    void permissiveSpf_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 +all"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_SPF_TOO_PERMISSIVE");
    }

    @Test
    void softfailSpf_notFlaggedAsPermissive() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 ~all"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SPF_TOO_PERMISSIVE");
    }

    @Test
    void missingDmarc_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_DMARC_MISSING");
    }

    @Test
    void dmarcPolicyNone_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=none"), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_DMARC_POLICY_NONE");
    }

    @Test
    void dmarcPolicyReject_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_DMARC_POLICY_NONE");
    }

    @Test
    void missingCaa_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), false, r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_CAA_MISSING");
    }

    @Test
    void missingDnskey_flaggedAsDnssecNotEnabled() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), false, r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNSSEC_NOT_ENABLED");
    }

    @Test
    void dmarcFindingAffectedAsset_isDmarcSubdomain() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        RawFinding dmarcMissing =
                findings.stream().filter(f -> f.ruleId().equals("DNS_DMARC_MISSING")).findFirst().orElseThrow();
        assertThat(dmarcMissing.affectedAsset()).isEqualTo("_dmarc.example.com");
    }

    @Test
    void mtaStsTxtMissing_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), false,
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_MTA_STS_MISSING");
    }

    @Test
    void mtaStsPolicyFileMissing_flaggedEvenIfTxtPresent() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), true, false,
                r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_MTA_STS_MISSING");
    }

    @Test
    void tlsRptMissing_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), false, r.bimiTxtPresent(), r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_TLS_RPT_MISSING");
    }

    @Test
    void bimiAbsent_flaggedAsInfo() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), false, r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        RawFinding bimi = findings.stream().filter(f -> f.ruleId().equals("EMAIL_BIMI_ABSENT")).findFirst().orElseThrow();
        assertThat(bimi.severity().name()).isEqualTo("INFO");
    }

    @Test
    void noDkimSelectorsFound_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), List.of(), r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_DKIM_NOT_DETECTED");
    }

    @Test
    void dkimSelectorFound_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_DKIM_NOT_DETECTED");
    }

    @Test
    void wildcardDnsDetected_flaggedAsSubdomainHygieneInfo() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(), true, r.danglingMxHosts());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        RawFinding wildcard =
                findings.stream().filter(f -> f.ruleId().equals("SUBDOMAIN_WILDCARD_DNS")).findFirst().orElseThrow();
        assertThat(wildcard.category().name()).isEqualTo("SUBDOMAIN_HYGIENE");
        assertThat(wildcard.severity().name()).isEqualTo("INFO");
    }

    @Test
    void noWildcard_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("SUBDOMAIN_WILDCARD_DNS");
    }

    @Test
    void dmarcMissingRua_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=reject"), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_DMARC_RUA_MISSING");
    }

    @Test
    void dmarcWithRua_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("EMAIL_DMARC_RUA_MISSING");
    }

    @Test
    void dmarcMissingEntirely_ruaCheckNotAlsoFlagged() {
        // DNS_DMARC_MISSING alone is the right signal when there's no record at all - EMAIL_DMARC_RUA_MISSING
        // would be redundant noise on top of it.
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("EMAIL_DMARC_RUA_MISSING");
    }

    @Test
    void dmarcPolicyNoneAndRuaMissing_bothFindingsFireIndependently() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=none"), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records)))
                .contains("DNS_DMARC_POLICY_NONE", "EMAIL_DMARC_RUA_MISSING");
    }

    @Test
    void danglingMxHost_flaggedHigh() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), List.of("abandoned-mail.example.net"));
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_MX_TO_DANGLING_HOST");
            assertThat(f.severity().name()).isEqualTo("HIGH");
            assertThat(f.affectedAsset()).isEqualTo("abandoned-mail.example.net");
        });
    }

    @Test
    void multipleDanglingMxHosts_eachFlaggedSeparately() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), List.of("mx1.example.net", "mx2.example.net"));
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings.stream().filter(f -> f.ruleId().equals("DNS_MX_TO_DANGLING_HOST")).count()).isEqualTo(2);
    }

    @Test
    void noDanglingMxHosts_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_MX_TO_DANGLING_HOST");
    }
}
