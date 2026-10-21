package org.freedonia.bloodhound.worker.ruleit;

import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.worker.modules.dns.DnsPostureModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/** Four zones, one resolver. Rules that cannot be true of the same zone are split across zones. */
@ExtendWith(RuleFixture.class)
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class DnsPostureRulesIT {

    @Test
    void emptyZoneFiresAbsenceRulesOnly() throws Exception {
        ModuleResult result = ScanSupport.run(new DnsPostureModule(), FixtureHosts.DNS_ABSENT);
        ScanSupport.assertRules(
                result,
                "DNS_SPF_MISSING",
                "DNS_DMARC_MISSING",
                "DNS_CAA_MISSING",
                "DNSSEC_NOT_ENABLED",
                "EMAIL_MTA_STS_MISSING",
                "EMAIL_TLS_RPT_MISSING",
                "EMAIL_BIMI_ABSENT",
                "DNS_DKIM_NOT_DETECTED");
        ScanSupport.assertAsset(result, "DNS_DMARC_MISSING", "_dmarc." + FixtureHosts.DNS_ABSENT);
        ScanSupport.assertAbsent(
                result,
                "DNS_SPF_MULTIPLE_RECORDS",
                "DNS_SPF_TOO_PERMISSIVE",
                "DNS_SPF_LOOKUP_LIMIT_EXCEEDED",
                "DNS_SPF_INCLUDE_DANGLING",
                "DNS_DMARC_POLICY_NONE",
                "EMAIL_DMARC_RUA_MISSING",
                "EMAIL_DMARC_PCT_BELOW_100",
                "DNS_DKIM_WEAK_KEY",
                "DNS_MX_TO_DANGLING_HOST",
                "DNS_SOA_SERIAL_STALE",
                "SUBDOMAIN_WILDCARD_DNS",
                "DNS_ZONE_TRANSFER_ALLOWED",
                "DNS_NS_LAME_DELEGATION");
    }

    @Test
    void badMailZoneFiresSpfDmarcDkimMxSerialAndWildcard() throws Exception {
        ModuleResult result = ScanSupport.run(new DnsPostureModule(), FixtureHosts.DNS_BADMAIL);
        ScanSupport.assertRules(
                result,
                "DNS_SPF_MULTIPLE_RECORDS",
                "DNS_SPF_TOO_PERMISSIVE",
                "DNS_SPF_LOOKUP_LIMIT_EXCEEDED",
                "DNS_SPF_INCLUDE_DANGLING",
                "DNS_DMARC_POLICY_NONE",
                "EMAIL_DMARC_RUA_MISSING",
                "EMAIL_DMARC_PCT_BELOW_100",
                "DNS_CAA_MISSING",
                "DNSSEC_NOT_ENABLED",
                "EMAIL_MTA_STS_MISSING",
                "EMAIL_TLS_RPT_MISSING",
                "EMAIL_BIMI_ABSENT",
                "DNS_DKIM_WEAK_KEY",
                "DNS_MX_TO_DANGLING_HOST",
                "DNS_SOA_SERIAL_STALE",
                "SUBDOMAIN_WILDCARD_DNS");
        ScanSupport.assertAsset(result, "DNS_SPF_INCLUDE_DANGLING", "spf-gone.example");
        ScanSupport.assertAsset(result, "DNS_MX_TO_DANGLING_HOST", "mail.gone.example");
        ScanSupport.assertAsset(result, "DNS_DKIM_WEAK_KEY", "default._domainkey." + FixtureHosts.DNS_BADMAIL);
        ScanSupport.assertAbsent(
                result,
                "DNS_SPF_MISSING",
                "DNS_DMARC_MISSING",
                "DNS_DKIM_NOT_DETECTED",
                "DNS_ZONE_TRANSFER_ALLOWED",
                "DNS_NS_LAME_DELEGATION");
    }

    @Test
    void axfrZoneTransfersAndIsNotLame() throws Exception {
        ModuleResult result = ScanSupport.run(new DnsPostureModule(), FixtureHosts.DNS_AXFR);
        ScanSupport.assertRules(result, "DNS_ZONE_TRANSFER_ALLOWED");
        ScanSupport.assertAsset(result, "DNS_ZONE_TRANSFER_ALLOWED", "ns1." + FixtureHosts.DNS_AXFR);
        ScanSupport.assertAbsent(result, "DNS_NS_LAME_DELEGATION");
    }

    @Test
    void refusedSoaIsLameAndDoesNotTransfer() throws Exception {
        ModuleResult result = ScanSupport.run(new DnsPostureModule(), FixtureHosts.DNS_LAME);
        ScanSupport.assertRules(result, "DNS_NS_LAME_DELEGATION");
        ScanSupport.assertAsset(result, "DNS_NS_LAME_DELEGATION", "ns1." + FixtureHosts.DNS_LAME);
        ScanSupport.assertAbsent(result, "DNS_ZONE_TRANSFER_ALLOWED", "DNS_SOA_SERIAL_STALE");
    }
}
