package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.Optional;

/**
 * Pure decision logic for NS-delegation subdomain takeover - distinct from
 * both {@link DanglingCnameDecisionLogic} (a subdomain CNAME'd to an
 * unclaimed *resource* within a shared multi-tenant service) and
 * {@link CloudBucketDecisionLogic} (a claimed bucket that's publicly
 * listable). This is a third, more severe variant: a subdomain delegated as
 * its own independent DNS *zone* (via NS records, not a CNAME) to a cloud
 * DNS provider, where the corresponding hosted zone has been deprovisioned.
 * Whoever notices can create a matching zone at that provider and become
 * fully authoritative for the subdomain - not just one hostname's HTTP
 * response like a CNAME takeover, but every record type, including MX for
 * mail interception.
 *
 * <p>"Is this delegation actually dangling" reuses the exact mechanic
 * {@link org.freedonia.bloodhound.worker.modules.dns.DnsZoneFetcher} already
 * established for the target's own apex (query the claimed nameserver
 * directly for a SOA record, see if it answers authoritatively) - a lame
 * delegation to a *known cloud DNS provider* specifically is what makes it
 * takeover-exploitable, versus lame-but-not-attacker-claimable delegation to
 * some other nameserver, which {@code DNS_NS_LAME_DELEGATION} already covers
 * for the apex case.
 */
final class NsTakeoverDecisionLogic {

    enum Provider {
        AWS_ROUTE53,
        AZURE_DNS,
        GOOGLE_CLOUD_DNS,
        DIGITALOCEAN
    }

    record Match(Provider provider) {}

    private NsTakeoverDecisionLogic() {}

    static Optional<Match> matchProvider(String nsHostname) {
        if (nsHostname == null || nsHostname.isBlank()) {
            return Optional.empty();
        }
        String lower = nsHostname.toLowerCase();
        // Route53 always assigns 4 NS across 4 different TLDs (.com/.net/.org/.co.uk) -
        // ".awsdns-" is the fixed substring common to all of them (e.g.
        // "ns-123.awsdns-45.com", "ns-678.awsdns-90.co.uk").
        if (lower.contains(".awsdns-")) {
            return Optional.of(new Match(Provider.AWS_ROUTE53));
        }
        // Azure DNS similarly spans 4 TLDs (.com/.net/.org/.info) sharing ".azure-dns.".
        if (lower.contains(".azure-dns.")) {
            return Optional.of(new Match(Provider.AZURE_DNS));
        }
        if (lower.contains(".googledomains.com")) {
            return Optional.of(new Match(Provider.GOOGLE_CLOUD_DNS));
        }
        if (lower.contains(".digitalocean.com")) {
            return Optional.of(new Match(Provider.DIGITALOCEAN));
        }
        return Optional.empty();
    }
}
