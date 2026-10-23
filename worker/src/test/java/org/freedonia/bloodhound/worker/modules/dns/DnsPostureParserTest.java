package org.freedonia.bloodhound.worker.modules.dns;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class DnsPostureParserTest {

    /** A real, live-captured 2048-bit RSA DKIM key (github.com's "google" selector) - strong enough that compliant() produces no DNS_DKIM_WEAK_KEY finding. */
    static final String STRONG_DKIM_TXT =
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj6T5sl/RwdSqGoYWaWaFbS2UAeyPrEmd0gogocmRfS441qwR8/0KB81Hw89P0l4YiFRrXYk7NVIGfyCRHAYYZUzCkGeOysI2EjgzLFhd/NEsbRzOEc/kWkK/RO6JFq/5lOn6M9AZw/ap9tds4JG9ApgNNdSpPxp9DmvpsOSgNMVflRxQFrk3kdS4RNAPKu/OPoA7dlR/A/pECryjRoYgENtDXzdnK70HgCekems6UDzxDj61cjyoKoXtEMF/QsaHEQ1Gjfv014rDJBsubk/kT5VqHkWHa/ia68Z5r228Ety/wFfQNjXTx/J7KGZ9GkZlKED659eiJcLnWcKDSiQlhwIDAQAB";

    /** A real, live-captured 1024-bit RSA DKIM key (Microsoft's "selector2", onmicrosoft.com) - the weak-key test's positive example. */
    static final String WEAK_DKIM_TXT =
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPkb8bu8RGWeJGk3hJrouZXIdZ+HTp/azRp8IUOHp5wKvPUAi/54PwuLscUjRk4Rh3hjIkMpKRfJJXPxWbrT7eMLric7f/S0h+qF4aqIiQqHFCDAYfMnN6V3Wbke2U5EGm0H/cAUYkaf2AtuHJ/rdY/EXaldAm00PgT9QQMez66QIDAQAB";

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
                List.of(),
                List.of(),
                null,
                1,
                List.of(STRONG_DKIM_TXT),
                false,
                null,
                null);
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
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_SPF_MISSING");
    }

    @Test
    void permissiveSpf_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 +all"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_SPF_TOO_PERMISSIVE");
    }

    @Test
    void softfailSpf_notFlaggedAsPermissive() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 ~all"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SPF_TOO_PERMISSIVE");
    }

    @Test
    void spfWithNoAllMechanismAtAll_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 include:_spf.example.com"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(),
                r.mtaStsTxtPresent(), r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(),
                r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(),
                r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(),
                r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_SPF_MISSING_ALL_MECHANISM");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
        // Not also flagged as too-permissive - that's specifically the +all/?all case, a
        // different (if related) gap.
        assertThat(ruleIds(findings)).doesNotContain("DNS_SPF_TOO_PERMISSIVE");
    }

    @Test
    void spfWithRedirect_notFlaggedAsMissingAll() {
        // redirect= takes over the all-mechanism's own role entirely per RFC 7208 6.1 - a record
        // ending in redirect= with no all mechanism of its own is correct, not a gap.
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 redirect=_spf.example.com"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(),
                r.mtaStsTxtPresent(), r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(),
                r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(),
                r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(),
                r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SPF_MISSING_ALL_MECHANISM");
    }

    @Test
    void spfWithHardFailAll_notFlaggedAsMissingAll() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant())))
                .doesNotContain("DNS_SPF_MISSING_ALL_MECHANISM");
    }

    @Test
    void spfWithBareAllMechanism_notFlaggedAsMissingAll() {
        // A bare "all" (no +/-/~/? qualifier) defaults to "+all" per RFC 7208 - still a real all
        // mechanism, not a missing one; DNS_SPF_TOO_PERMISSIVE's own endsWith check wouldn't catch
        // this exact bare form, but it's still not this rule's gap to report.
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 include:_spf.example.com all"), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(),
                r.mtaStsTxtPresent(), r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(),
                r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(),
                r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(),
                r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SPF_MISSING_ALL_MECHANISM");
    }

    @Test
    void missingDmarc_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_DMARC_MISSING");
    }

    @Test
    void dmarcPolicyNone_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=none"), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
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
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_CAA_MISSING");
    }

    @Test
    void missingDnskey_flaggedAsDnssecNotEnabled() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), false, r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNSSEC_NOT_ENABLED");
    }

    @Test
    void dmarcFindingAffectedAsset_isDmarcSubdomain() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
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
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_MTA_STS_MISSING");
    }

    @Test
    void mtaStsPolicyFileMissing_flaggedEvenIfTxtPresent() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), true, false,
                r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_MTA_STS_MISSING");
    }

    @Test
    void tlsRptMissing_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), false, r.bimiTxtPresent(), r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("EMAIL_TLS_RPT_MISSING");
    }

    @Test
    void bimiAbsent_flaggedAsInfo() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), false, r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        RawFinding bimi = findings.stream().filter(f -> f.ruleId().equals("EMAIL_BIMI_ABSENT")).findFirst().orElseThrow();
        assertThat(bimi.severity().name()).isEqualTo("INFO");
    }

    @Test
    void noDkimSelectorsFound_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), List.of(), r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), List.of(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_DKIM_NOT_DETECTED");
    }

    @Test
    void dkimSelectorFound_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_DKIM_NOT_DETECTED");
    }

    @Test
    void strongDkimKey_notFlaggedAsWeak() {
        // compliant()'s own DKIM record is the real, live-captured 2048-bit github.com key.
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_DKIM_WEAK_KEY");
    }

    @Test
    void weakDkimKey_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), List.of("selector2"),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(),
                List.of(WEAK_DKIM_TXT), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_DKIM_WEAK_KEY");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
            assertThat(f.affectedAsset()).isEqualTo("selector2._domainkey.example.com");
            assertThat(f.evidence()).containsEntry("selector", "selector2").containsEntry("keyBits", 1024);
        });
    }

    @Test
    void multipleDkimSelectors_onlyWeakOnesFlagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), List.of("google", "selector2"),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(),
                List.of(STRONG_DKIM_TXT, WEAK_DKIM_TXT), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings.stream().filter(f -> f.ruleId().equals("DNS_DKIM_WEAK_KEY")).toList()).hasSize(1);
    }

    @Test
    void wildcardDnsDetected_flaggedAsSubdomainHygieneInfo() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(), true, r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
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
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
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
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("EMAIL_DMARC_RUA_MISSING");
    }

    @Test
    void dmarcPolicyNoneAndRuaMissing_bothFindingsFireIndependently() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=none"), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records)))
                .contains("DNS_DMARC_POLICY_NONE", "EMAIL_DMARC_RUA_MISSING");
    }

    @Test
    void danglingMxHost_flaggedHigh() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), List.of("abandoned-mail.example.net"), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
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
                r.wildcardDnsDetected(), List.of("mx1.example.net", "mx2.example.net"), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings.stream().filter(f -> f.ruleId().equals("DNS_MX_TO_DANGLING_HOST")).count()).isEqualTo(2);
    }

    @Test
    void noDanglingMxHosts_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_MX_TO_DANGLING_HOST");
    }

    @Test
    void multipleSpfRecords_flaggedHigh() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                List.of("v=spf1 include:_spf.example.com -all", "v=spf1 include:other.example.com -all"),
                r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_SPF_MULTIPLE_RECORDS");
            assertThat(f.severity().name()).isEqualTo("HIGH");
        });
    }

    @Test
    void spfUsesPtrMechanism_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(),
                r.spfLookupCount(), r.dkimRawTxtFound(), true, r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_SPF_PTR_MECHANISM_DEPRECATED");
    }

    @Test
    void spfWithoutPtrMechanism_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant())))
                .doesNotContain("DNS_SPF_PTR_MECHANISM_DEPRECATED");
    }

    @Test
    void singleSpfRecord_notFlaggedAsMultiple() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_SPF_MULTIPLE_RECORDS");
    }

    @Test
    void spfLookupCountOver10_flaggedHigh() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), 11, r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_SPF_LOOKUP_LIMIT_EXCEEDED");
            assertThat(f.severity().name()).isEqualTo("HIGH");
            assertThat(f.evidence()).containsEntry("lookupCount", 11).containsEntry("limit", 10);
        });
    }

    @Test
    void spfLookupCountExactlyAt10_notFlagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), 10, r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SPF_LOOKUP_LIMIT_EXCEEDED");
    }

    @Test
    void spfLookupCountWellUnderLimit_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant())))
                .doesNotContain("DNS_SPF_LOOKUP_LIMIT_EXCEEDED");
    }

    @Test
    void nullSpfLookupCount_notFlagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(), null, r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SPF_LOOKUP_LIMIT_EXCEEDED");
    }

    @Test
    void danglingSpfInclude_flaggedHigh() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), List.of("_spf.abandoned-esp.example.net"), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_SPF_INCLUDE_DANGLING");
            assertThat(f.severity().name()).isEqualTo("HIGH");
            assertThat(f.affectedAsset()).isEqualTo("_spf.abandoned-esp.example.net");
        });
    }

    @Test
    void noDanglingSpfIncludes_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_SPF_INCLUDE_DANGLING");
    }

    @Test
    void dmarcPctBelow100_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"), r.caaPresent(),
                r.dnskeyPresent(), r.mtaStsTxtPresent(), r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(),
                r.bimiTxtPresent(), r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(),
                r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("EMAIL_DMARC_PCT_BELOW_100");
            assertThat(f.evidence()).containsEntry("pct", 50);
        });
    }

    @Test
    void dmarcPctAbsent_defaultsTo100_notFlagged() {
        // pct= defaults to 100 per RFC 7489 when absent - compliant()'s own DMARC record has no
        // pct= tag at all, and must not be treated as "below 100".
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("EMAIL_DMARC_PCT_BELOW_100");
    }

    @Test
    void dmarcPct100Explicit_notFlagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), List.of("v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"), r.caaPresent(),
                r.dnskeyPresent(), r.mtaStsTxtPresent(), r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(),
                r.bimiTxtPresent(), r.dkimSelectorsFound(), r.wildcardDnsDetected(), r.danglingMxHosts(),
                r.danglingSpfIncludes(), r.soaSerial(), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("EMAIL_DMARC_PCT_BELOW_100");
    }

    private static DnsRecords withDmarc(String dmarcRecord) {
        DnsRecords r = compliant();
        return new DnsRecords(
                r.txtRecords(), List.of(dmarcRecord), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(),
                r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(),
                r.soaRetrySeconds());
    }

    @Test
    void dmarcSubdomainPolicyWeaker_flagged() {
        DnsRecords records = withDmarc("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com");
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_DMARC_SUBDOMAIN_POLICY_WEAKER");
            assertThat(f.severity().name()).isEqualTo("MEDIUM");
        });
        // A rules-parity review found the old substring check (`v.contains("p=none")`) matched
        // the literal "p=none" inside "sp=none" here, wrongly firing DNS_DMARC_POLICY_NONE even
        // though the actual main policy (p=) is reject, not none - a different, already-correctly-
        // flagged gap (DNS_DMARC_SUBDOMAIN_POLICY_WEAKER, asserted above) got misreported as this
        // one too.
        assertThat(ruleIds(findings)).doesNotContain("DNS_DMARC_POLICY_NONE");
    }

    @Test
    void dmarcSubdomainPolicySameStrength_notFlagged() {
        DnsRecords records = withDmarc("v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com");
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records)))
                .doesNotContain("DNS_DMARC_SUBDOMAIN_POLICY_WEAKER");
    }

    @Test
    void dmarcSubdomainPolicyStronger_notFlagged() {
        // sp= stricter than p= is a perfectly reasonable, intentional hardening choice - not a gap.
        DnsRecords records = withDmarc("v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com");
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records)))
                .doesNotContain("DNS_DMARC_SUBDOMAIN_POLICY_WEAKER");
    }

    @Test
    void dmarcNoSubdomainPolicyTag_notFlagged() {
        // sp= absent means p= applies to subdomains too, per RFC 7489 default - not a gap.
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant())))
                .doesNotContain("DNS_DMARC_SUBDOMAIN_POLICY_WEAKER");
    }

    @Test
    void dmarcSubdomainPolicyQuarantineWeakerThanReject_flagged() {
        DnsRecords records = withDmarc("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com");
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records)))
                .contains("DNS_DMARC_SUBDOMAIN_POLICY_WEAKER");
    }

    @Test
    void soaSerialEncodingAVeryOldDate_flaggedLow() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), 2015010101L, r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_SOA_SERIAL_STALE");
            assertThat(f.severity().name()).isEqualTo("LOW");
        });
    }

    @Test
    void soaSerialEncodingARecentDate_notFlagged() {
        String recentSerial = java.time.LocalDate.now(java.time.ZoneOffset.UTC)
                .minusMonths(1)
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd")) + "01";
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), Long.parseLong(recentSerial), r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SOA_SERIAL_STALE");
    }

    @Test
    void soaSerialNotDateShaped_notFlagged_ratherThanMisinterpreted() {
        // A plain incrementing counter (equally valid per RFC 1035) rather than YYYYMMDDnn -
        // must not be guessed at as a date, in either direction.
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), 42L, r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), r.soaRefreshSeconds(), r.soaRetrySeconds());
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SOA_SERIAL_STALE");
    }

    @Test
    void nullSoaSerial_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant()))).doesNotContain("DNS_SOA_SERIAL_STALE");
    }

    @Test
    void soaRetryEqualsRefresh_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(),
                r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), 7200L, 7200L);
        List<RawFinding> findings = DnsPostureParser.parse("example.com", records);
        assertThat(findings).anySatisfy(f -> {
            assertThat(f.ruleId()).isEqualTo("DNS_SOA_RETRY_EXCEEDS_REFRESH");
            assertThat(f.severity().name()).isEqualTo("LOW");
            assertThat(f.evidence()).containsEntry("refreshSeconds", 7200L).containsEntry("retrySeconds", 7200L);
        });
    }

    @Test
    void soaRetryExceedsRefresh_flagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(),
                r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), 3600L, 7200L);
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).contains("DNS_SOA_RETRY_EXCEEDS_REFRESH");
    }

    @Test
    void soaRetryBelowRefresh_notFlagged() {
        DnsRecords r = compliant();
        DnsRecords records = new DnsRecords(
                r.txtRecords(), r.dmarcTxtRecords(), r.caaPresent(), r.dnskeyPresent(), r.mtaStsTxtPresent(),
                r.mtaStsPolicyFilePresent(), r.tlsRptTxtPresent(), r.bimiTxtPresent(), r.dkimSelectorsFound(),
                r.wildcardDnsDetected(), r.danglingMxHosts(), r.danglingSpfIncludes(), r.soaSerial(),
                r.spfLookupCount(), r.dkimRawTxtFound(), r.spfUsesPtrMechanism(), 86400L, 7200L);
        assertThat(ruleIds(DnsPostureParser.parse("example.com", records))).doesNotContain("DNS_SOA_RETRY_EXCEEDS_REFRESH");
    }

    @Test
    void nullSoaTiming_notFlagged() {
        assertThat(ruleIds(DnsPostureParser.parse("example.com", compliant())))
                .doesNotContain("DNS_SOA_RETRY_EXCEEDS_REFRESH");
    }

    @Test
    void tryParseSoaSerialAsDate_invalidMonthOrDay_returnsNull() {
        assertThat(DnsPostureParser.tryParseSoaSerialAsDate(2026139901L)).isNull(); // month 13
    }
}
